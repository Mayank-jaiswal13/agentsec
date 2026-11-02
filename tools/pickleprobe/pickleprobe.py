#!/usr/bin/env python3
"""pickleprobe: offline scanner for code-execution risk in pickle-based model files.

Reads pickle opcodes with pickletools (it never unpickles anything) inside raw
pickles (.pkl/.pickle/.joblib/.bin/...), PyTorch zip checkpoints (.pt/.pth/.ckpt/.bin),
NumPy .npy/.npz object arrays and Keras .keras archives, and reports which Python
callables a load would import. Standard library only; no network.

Rules
  PP01 critical  dangerous import (os/subprocess/eval/exec/socket/...)
  PP02 medium    import not on the safe allowlist (review it)
  PP03 medium    pickle stream could not be fully parsed (scanners that stop early can be bypassed)
  PP04 high      pickle data hidden in a file whose name claims a safe format
  PP05 medium    NumPy object array (needs allow_pickle=True)
  PP06 high      archive member with absolute or ../ path
  PP07 high      Keras Lambda layer / custom code in a .keras config
  PP08 info      pickle-based format (prefer safetensors)
Exit codes: 0 clean, 1 findings at/above --fail-on, 2 usage/input error.
"""
import argparse, ast, fnmatch, io, json, os, pickletools, re, struct, sys, zipfile

__version__ = "0.1.0"
SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RULES = {
    "PP01": ("critical", "dangerous import in pickle"),
    "PP02": ("medium", "import not on safe allowlist"),
    "PP03": ("medium", "pickle stream could not be fully parsed"),
    "PP04": ("high", "pickle data disguised as a safe format"),
    "PP05": ("medium", "NumPy object array requires allow_pickle"),
    "PP06": ("high", "archive member path escapes the archive"),
    "PP07": ("high", "Keras Lambda layer or custom code"),
    "PP08": ("info", "pickle-based format"),
}
PICKLE_EXT = {".pkl", ".pickle", ".joblib", ".pt", ".pth", ".ckpt", ".bin", ".dat", ".p", ".sav", ".model"}
SAFE_CLAIM_EXT = {".safetensors", ".json", ".txt", ".md", ".png", ".jpg", ".jpeg", ".gif", ".csv",
                  ".yaml", ".yml", ".onnx", ".gguf", ".tflite", ".msgpack", ".wav", ".mp3"}
SCAN_EXT = PICKLE_EXT | {".npy", ".npz", ".keras"} | SAFE_CLAIM_EXT

# module -> names ("*" = any name in that module) that let a pickle run code or touch the system.
DANGEROUS = {
    "os": "*", "posix": "*", "nt": "*", "subprocess": "*", "sys": "*", "socket": "*", "shutil": "*",
    "runpy": "*", "importlib": "*", "pty": "*", "webbrowser": "*", "ctypes": "*", "marshal": "*",
    "code": "*", "commands": "*", "multiprocessing": "*", "asyncio": "*", "signal": "*",
    "requests": "*", "httpx": "*", "urllib": "*", "urllib.request": "*", "http.client": "*",
    "ftplib": "*", "smtplib": "*", "telnetlib": "*", "pip": "*", "setuptools": "*", "dill": "*",
    "pickle": "*", "_pickle": "*", "cPickle": "*", "shelve": "*", "tempfile": "*", "glob": "*",
    "pathlib": "*", "io": {"open", "FileIO", "open_code"}, "_io": {"open", "FileIO"}, "platform": "*", "pdb": "*", "bdb": "*", "timeit": "*",
    "builtins": {"eval", "exec", "compile", "__import__", "open", "getattr", "setattr", "delattr",
                 "globals", "locals", "vars", "input", "breakpoint", "help", "exit", "quit", "memoryview"},
    "__builtin__": {"eval", "exec", "compile", "__import__", "open", "getattr", "setattr", "execfile",
                    "file", "input", "globals"},
    "operator": {"attrgetter", "methodcaller", "getitem"},
    "functools": {"partial", "reduce"},
    "types": {"CodeType", "FunctionType", "LambdaType", "MethodType"},
    "torch": {"load"}, "torch.serialization": {"load"}, "numpy": {"load"}, "numpy.lib.npyio": {"load"},
    "joblib": {"load"},
}
SAFE = {
    "collections": {"OrderedDict", "defaultdict", "deque", "Counter"},
    "builtins": {"set", "frozenset", "dict", "list", "tuple", "bytearray", "bytes", "slice", "range",
                 "complex", "int", "float", "str", "bool", "object", "type"},
    "__builtin__": {"set", "frozenset", "bytearray", "slice", "complex", "object"},
    "copy_reg": {"_reconstructor"}, "copyreg": {"_reconstructor"}, "_codecs": {"encode"},
    "datetime": {"datetime", "date", "time", "timedelta", "timezone"}, "decimal": {"Decimal"},
    "uuid": {"UUID"},
    "torch": {"FloatStorage", "DoubleStorage", "HalfStorage", "BFloat16Storage", "LongStorage",
              "IntStorage", "ShortStorage", "CharStorage", "ByteStorage", "BoolStorage", "Size",
              "float32", "float16", "bfloat16", "float64", "int64", "int32", "int8", "uint8", "bool",
              "device", "dtype", "Tensor", "UntypedStorage", "TypedStorage"},
    "torch._utils": {"_rebuild_tensor", "_rebuild_tensor_v2", "_rebuild_parameter",
                     "_rebuild_parameter_with_state", "_rebuild_qtensor", "_rebuild_sparse_tensor",
                     "_rebuild_device_tensor_from_numpy", "_rebuild_meta_tensor_no_storage"},
    "torch._tensor": {"_rebuild_from_type_v2"}, "torch.nn.parameter": {"Parameter"},
    "torch.storage": {"_load_from_bytes"},
    "numpy": {"ndarray", "dtype", "float32", "float64", "int64", "int32", "uint8", "bool_"},
    "numpy.core.multiarray": {"_reconstruct", "scalar"}, "numpy._core.multiarray": {"_reconstruct", "scalar"},
    "numpy.dtypes": "*",
}
STRING_OPS = {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE", "STRING", "BINSTRING",
              "SHORT_BINSTRING"}


class Finding:
    def __init__(self, rule, path, msg, where="", severity=None):
        self.rule, self.path, self.msg, self.where = rule, path, msg, where
        self.severity = severity or RULES[rule][0]

    def as_dict(self):
        return {"rule": self.rule, "severity": self.severity, "title": RULES[self.rule][1],
                "path": self.path, "where": self.where, "message": self.msg}


def _match(table, module, name):
    names = table.get(module)
    if names is None:
        return False
    return names == "*" or name in names


def classify_import(module, name, allow=()):
    """Return 'dangerous', 'safe' or 'unknown' for module.name."""
    full = "%s.%s" % (module, name)
    if any(fnmatch.fnmatchcase(full, g) for g in allow):
        return "safe"
    if _match(SAFE, module, name):
        return "safe"
    root = module.split(".")[0]
    if _match(DANGEROUS, module, name) or (module != root and DANGEROUS.get(root) == "*"):
        return "dangerous"
    return "unknown"


def pickle_imports(data):
    """Parse every pickle stream in data. Returns (imports, error, n_streams).
    imports: list of (module, name, byte offset). Never executes the pickle."""
    imports, pos, streams, err = [], 0, 0, None
    while pos < len(data):
        if streams and not data[pos:pos + 1].strip(b"\x00\n\r\t "):
            break
        if streams and data[pos:pos + 1] != b"\x80":
            break  # trailing non-pickle bytes (e.g. legacy torch storages)
        memo, strings, stop = {}, [], None
        try:
            for op, arg, off in pickletools.genops(io.BytesIO(data[pos:])):
                n = op.name
                if n in STRING_OPS:
                    v = arg.decode("latin-1") if isinstance(arg, bytes) else str(arg)
                    strings.append(v)
                elif n == "MEMOIZE":
                    if strings:
                        memo[len(memo)] = strings[-1]
                elif n in ("BINPUT", "LONG_BINPUT", "PUT"):
                    if strings:
                        memo[arg] = strings[-1]
                elif n in ("BINGET", "LONG_BINGET", "GET"):
                    if arg in memo:
                        strings.append(memo[arg])
                elif n in ("GLOBAL", "INST"):
                    mod, _, name = str(arg).partition(" ")
                    imports.append((mod, name, pos + off))
                elif n == "STACK_GLOBAL":
                    if len(strings) >= 2:
                        imports.append((strings[-2], strings[-1], pos + off))
                    else:
                        imports.append(("?", "?", pos + off))
                elif n == "STOP":
                    stop = off
            streams += 1
            if stop is None:
                raise ValueError("no STOP opcode")
            pos += stop + 1
        except Exception as e:  # truncated / malformed / unknown opcode
            err = "%s at stream %d: %s" % (type(e).__name__, streams + 1, e)
            break
    return imports, err, streams


def looks_like_pickle(data):
    return len(data) >= 2 and data[0] == 0x80 and 0 <= data[1] <= 5


def _scan_pickle_bytes(data, path, where, allow, out):
    imports, err, _ = pickle_imports(data)
    seen = set()
    for mod, name, off in imports:
        key = (mod, name)
        if key in seen:
            continue
        seen.add(key)
        w = "%s@%d" % (where, off) if where else "offset %d" % off
        if (mod, name) == ("?", "?"):
            out.append(Finding("PP02", path, "STACK_GLOBAL import whose name could not be resolved statically", w))
            continue
        kind = classify_import(mod, name, allow)
        if kind == "dangerous":
            out.append(Finding("PP01", path, "imports %s.%s, which can run code or touch the system on load" % (mod, name), w))
        elif kind == "unknown":
            out.append(Finding("PP02", path, "imports %s.%s; not on the safe allowlist, review before loading" % (mod, name), w))
    if err:
        out.append(Finding("PP03", path, err, where))


def _npy_header(data):
    if not data.startswith(b"\x93NUMPY") or len(data) < 10:
        return None, 0
    major = data[6]
    if major == 1:
        hlen, start = struct.unpack("<H", data[8:10])[0], 10
    else:
        hlen, start = struct.unpack("<I", data[8:12])[0], 12
    try:
        hdr = ast.literal_eval(data[start:start + hlen].decode("latin-1"))
    except Exception:
        return None, 0
    return hdr, start + hlen


def _scan_npy(data, path, where, allow, out):
    hdr, body = _npy_header(data)
    if hdr is None:
        out.append(Finding("PP03", path, "unreadable .npy header", where))
        return
    descr = str(hdr.get("descr", ""))
    if "O" in descr:
        out.append(Finding("PP05", path, "object dtype %r: np.load needs allow_pickle=True and unpickles the payload" % descr, where))
        _scan_pickle_bytes(data[body:], path, (where + ":" if where else "") + "payload", allow, out)


def _scan_zip(fp, path, allow, out, ext):
    try:
        zf = zipfile.ZipFile(fp)
    except zipfile.BadZipFile as e:
        out.append(Finding("PP03", path, "bad zip archive: %s" % e))
        return
    with zf:
        names = zf.namelist()
        for n in names:
            if n.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", n) or ".." in re.split(r"[/\\]", n):
                out.append(Finding("PP06", path, "member path %r is absolute or contains '..'" % n, n))
        pkls = [n for n in names if n.endswith((".pkl", ".pickle")) or os.path.basename(n) == "data.pkl"]
        if pkls:
            out.append(Finding("PP08", path, "PyTorch/zip checkpoint with pickle members %s; prefer safetensors" % ", ".join(pkls[:3])))
        for n in names:
            info = zf.getinfo(n)
            if info.is_dir() or info.file_size > 512 * 1024 * 1024:
                continue
            low = n.lower()
            if n in pkls:
                _scan_pickle_bytes(zf.read(n), path, n, allow, out)
            elif low.endswith(".npy"):
                _scan_npy(zf.read(n), path, n, allow, out)
            elif ext == ".keras" and os.path.basename(low) == "config.json":
                _scan_keras_config(zf.read(n), path, n, out)


def _scan_keras_config(raw, path, where, out):
    try:
        cfg = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        out.append(Finding("PP03", path, "unparseable Keras config.json", where))
        return
    stack = [cfg]
    while stack:
        o = stack.pop()
        if isinstance(o, dict):
            if o.get("class_name") == "Lambda":
                nm = (o.get("config") or {}).get("name", "?") if isinstance(o.get("config"), dict) else "?"
                out.append(Finding("PP07", path, "Lambda layer %r carries serialized Python code executed on load (safe_mode=False)" % nm, where))
                continue
            if "function" in o and isinstance(o.get("function"), (list, dict)) and o.get("class_name") != "Lambda":
                out.append(Finding("PP07", path, "custom serialized function in layer config", where, "medium"))
            stack.extend(o.values())
        elif isinstance(o, list):
            stack.extend(o)


def scan_file(path, allow=()):
    out = []
    ext = os.path.splitext(path)[1].lower()
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise SystemExit("pickleprobe: cannot read %s: %s" % (path, e))
    if data[:4] == b"PK\x03\x04":
        if ext in SAFE_CLAIM_EXT:
            out.append(Finding("PP04", path, "zip archive named %s; inspect what it really contains" % ext, severity="medium"))
        _scan_zip(io.BytesIO(data), path, allow, out, ext)
    elif data.startswith(b"\x93NUMPY"):
        _scan_npy(data, path, "", allow, out)
    elif looks_like_pickle(data) or (ext in PICKLE_EXT and data[:1] in (b"(", b"c", b"}", b"]")):
        if ext in SAFE_CLAIM_EXT:
            out.append(Finding("PP04", path, "file named %s actually contains pickle data" % ext))
        else:
            out.append(Finding("PP08", path, "pickle-based file; loading it can execute code. Prefer safetensors"))
        _scan_pickle_bytes(data, path, "", allow, out)
    return out


def iter_files(paths, all_files=False):
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in (".git", "node_modules", "__pycache__"))
                for fn in sorted(files):
                    if all_files or os.path.splitext(fn)[1].lower() in SCAN_EXT:
                        yield os.path.join(root, fn)
        elif os.path.isfile(p):
            yield p
        else:
            raise SystemExit("pickleprobe: no such file or directory: %s" % p)


def scan(paths, allow=(), all_files=False):
    files, findings = 0, []
    for f in iter_files(paths, all_files):
        files += 1
        findings.extend(scan_file(f, allow))
    return files, findings


def to_sarif(findings):
    rules = [{"id": k, "name": v[1], "shortDescription": {"text": v[1]}} for k, v in RULES.items()]
    lvl = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    res = [{"ruleId": f.rule, "level": lvl[f.severity], "message": {"text": f.msg + (" [%s]" % f.where if f.where else "")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path.replace(os.sep, "/")}}}]}
           for f in findings]
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "pickleprobe", "version": __version__, "rules": rules}},
                      "results": res}]}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pickleprobe", description="Scan pickle-based model files for code-execution risk without loading them.")
    ap.add_argument("paths", nargs="+", help="files or directories")
    ap.add_argument("--allow", action="append", default=[], metavar="GLOB", help="treat module.name matching GLOB as safe (repeatable)")
    ap.add_argument("--all-files", action="store_true", help="in directories, scan every file, not just known extensions")
    ap.add_argument("--min-severity", choices=list(SEV), default="info")
    ap.add_argument("--fail-on", choices=list(SEV) + ["none"], default="medium")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--json", action="store_true")
    g.add_argument("--sarif", action="store_true")
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(argv)
    try:
        files, findings = scan(a.paths, a.allow, a.all_files)
    except SystemExit as e:
        print(e, file=sys.stderr)
        return 2
    shown = [f for f in findings if SEV[f.severity] >= SEV[a.min_severity]]
    shown.sort(key=lambda f: (-SEV[f.severity], f.path, f.rule))
    if a.json:
        print(json.dumps({"files_scanned": files, "findings": [f.as_dict() for f in shown]}, indent=2))
    elif a.sarif:
        print(json.dumps(to_sarif(shown), indent=2))
    else:
        for f in shown:
            print("%-8s %s %s%s\n         %s" % (f.severity.upper(), f.rule, f.path, " [%s]" % f.where if f.where else "", f.msg))
        counts = {}
        for f in shown:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        print("\n%d file(s) scanned, %d finding(s)%s" % (files, len(shown),
              (": " + ", ".join("%d %s" % (counts[s], s) for s in sorted(counts, key=lambda s: -SEV[s]))) if counts else ""))
    if a.fail_on != "none" and any(SEV[f.severity] >= SEV[a.fail_on] for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
