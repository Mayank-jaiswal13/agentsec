#!/usr/bin/env python3
"""Generate FAKE example model files into examples/risky and examples/clean.

Nothing here is ever unpickled. The "malicious" files only *reference* os.system /
builtins.exec with a harmless echo string so the scanner has something to find.
Binary examples are generated, not committed.
"""
import json, os, pickle, struct, sys, zipfile
from collections import OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))


def glob_pickle(module, name, arg="echo pickleprobe-demo", proto=2):
    """Hand-built pickle: module.name(arg). Protocol 2 uses GLOBAL, 4 uses STACK_GLOBAL."""
    a = arg.encode()
    if proto >= 4:
        m, n = module.encode(), name.encode()
        body = (b"\x8c" + bytes([len(m)]) + m + b"\x94" + b"\x8c" + bytes([len(n)]) + n + b"\x94\x93\x94"
                + b"\x8c" + bytes([len(a)]) + a + b"\x94\x85\x94R\x94.")
        return b"\x80\x04" + body
    return (b"\x80\x02c" + module.encode() + b"\n" + name.encode() + b"\n"
            + b"X" + struct.pack("<I", len(a)) + a + b"\x85R.")


def torch_zip(path, pkl_bytes, extra=None):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("archive/data.pkl", pkl_bytes)
        z.writestr("archive/version", "3\n")
        z.writestr("archive/data/0", b"\x00" * 16)
        for k, v in (extra or {}).items():
            z.writestr(k, v)


def tensor_pickle():
    # what a benign torch state_dict pickle references
    return (b"\x80\x02ccollections\nOrderedDict\n)R(X\x06\x00\x00\x00weightctorch._utils\n_rebuild_tensor_v2\n"
            b"(ctorch\nFloatStorage\n)tRsb.")


def npy(path, descr, payload=b""):
    hdr = repr({"descr": descr, "fortran_order": False, "shape": (2,)}).encode()
    hdr += b" " * (63 - (len(hdr) + 10) % 64) + b"\n"
    with open(path, "wb") as f:
        f.write(b"\x93NUMPY\x01\x00" + struct.pack("<H", len(hdr)) + hdr + payload)


def main(out=HERE):
    risky, clean = os.path.join(out, "risky"), os.path.join(out, "clean")
    os.makedirs(risky, exist_ok=True)
    os.makedirs(clean, exist_ok=True)
    def w(d, n, b):
        with open(os.path.join(d, n), "wb") as f:
            f.write(b)
    # risky
    w(risky, "reverse_shell.pkl", glob_pickle("os", "system"))
    w(risky, "stack_global_exec.pickle", glob_pickle("builtins", "exec", "print('pickleprobe-demo')", proto=4))
    w(risky, "unknown_class.joblib", glob_pickle("sklearn_plugin_fake", "Loader", "x"))
    w(risky, "model.safetensors", glob_pickle("subprocess", "Popen"))  # disguised
    w(risky, "truncated.pkl", glob_pickle("collections", "OrderedDict")[:-3])
    torch_zip(os.path.join(risky, "backdoored_model.pt"), glob_pickle("posix", "system"),
              {"../../evil.sh": "echo pickleprobe-demo\n"})
    npy(os.path.join(risky, "objects.npy"), "|O", glob_pickle("os", "system"))
    with zipfile.ZipFile(os.path.join(risky, "lambda_model.keras"), "w") as z:
        z.writestr("config.json", json.dumps({"class_name": "Sequential", "config": {"layers": [
            {"class_name": "Dense", "config": {"name": "dense"}},
            {"class_name": "Lambda", "config": {"name": "fake_lambda", "function": ["FAKE-EXAMPLE-BYTECODE", None, None]}}]}}))
        z.writestr("metadata.json", "{}")
    # clean
    w(clean, "plain_dict.pkl", pickle.dumps({"weights": [0.1, 0.2], "names": OrderedDict(a=1)}, protocol=4))
    torch_zip(os.path.join(clean, "state_dict.pt"), tensor_pickle())
    npy(os.path.join(clean, "floats.npy"), "<f4", b"\x00" * 8)
    w(clean, "model.safetensors", struct.pack("<Q", 2) + b"{}")
    return risky, clean


if __name__ == "__main__":
    r, c = main(sys.argv[1] if len(sys.argv) > 1 else HERE)
    print("wrote", r, "and", c)
