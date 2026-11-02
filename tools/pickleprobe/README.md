# pickleprobe

Scans pickle-based model files for code-execution risk **without loading them**.

Loading a pickle (`torch.load`, `joblib.load`, `pickle.load`, `np.load(allow_pickle=True)`)
can run any Python the file asks for. pickleprobe walks the pickle opcodes with the standard
library's `pickletools` (it never unpickles) and reports which Python callables a load would
import, so you can check a model downloaded from a hub or handed over by a teammate before
anything touches it.

Supported inputs: raw pickles (`.pkl`, `.pickle`, `.joblib`, `.bin`, `.dat`, ...), PyTorch zip
checkpoints (`.pt`, `.pth`, `.ckpt`, `.bin`), NumPy `.npy` / `.npz`, and Keras `.keras` archives.
Files are recognised by their bytes, not only their extension, so a pickle renamed to
`model.safetensors` is caught.

## Rules

| Rule | Severity | Finding |
|---|---|---|
| PP01 | critical | Dangerous import: `os`/`posix`/`nt`, `subprocess`, `builtins.eval/exec/getattr/open/__import__`, `socket`, `runpy`, `importlib`, `ctypes`, `marshal`, network clients, `operator.attrgetter`, `functools.partial`, `types.CodeType`, nested `pickle`/`torch.load` and more |
| PP02 | medium | Import that is not on the safe allowlist (tensor rebuilders, `OrderedDict`, NumPy reconstructors, plain builtins). Review it, or allow it with `--allow` |
| PP03 | medium | Pickle stream, `.npy` header, zip or Keras config could not be fully parsed. Scanners that give up early are a known bypass, so this is not ignored |
| PP04 | high | Pickle data in a file named like a safe format (`.safetensors`, `.json`, `.png`, `.onnx`, `.gguf`, ...); medium for a zip with such a name |
| PP05 | medium | NumPy object array, which needs `allow_pickle=True` and unpickles its payload (the payload is scanned too) |
| PP06 | high | Archive member with an absolute path or `..` |
| PP07 | high | Keras `Lambda` layer (serialized Python code); medium for other serialized functions |
| PP08 | info | The file uses a pickle-based format at all. Prefer safetensors |

## Usage

```sh
cd tools/pickleprobe
python3 examples/make_examples.py           # writes FAKE examples/risky and examples/clean
python3 pickleprobe.py examples/risky       # 17 findings, exit 1
python3 pickleprobe.py examples/clean       # info only, exit 0
python3 pickleprobe.py ~/models --json --min-severity medium
python3 pickleprobe.py model.pt --allow 'mylib.models.*' --sarif > pickleprobe.sarif
```

Options: `--allow GLOB` (repeatable, matches `module.name`), `--all-files` (scan every file in a
directory, not just known extensions), `--min-severity`, `--fail-on` (default `medium`, or
`none`), `--json`, `--sarif`. Exit codes: `0` clean, `1` findings at or above `--fail-on`,
`2` usage or input error.

Example output:

```
CRITICAL PP01 examples/risky/backdoored_model.pt [archive/data.pkl@2]
         imports posix.system, which can run code or touch the system on load
HIGH     PP04 examples/risky/model.safetensors
         file named .safetensors actually contains pickle data
MEDIUM   PP05 examples/risky/objects.npy
         object dtype '|O': np.load needs allow_pickle=True and unpickles the payload
```

The example files are generated, not committed. The "malicious" ones only *reference*
`os.system` or `builtins.exec` with a harmless `echo pickleprobe-demo` string, and nothing in
this tool or its tests ever unpickles them.

## Known limits

- It is a static allowlist/denylist check, not a proof of safety. A file with no PP01 can still
  be harmful through an allowed callable used in an unexpected way, or a library class whose
  own `__setstate__` / `__reduce__` does something dangerous. Treat PP02 seriously.
- `STACK_GLOBAL` names are resolved by tracking string pushes and the memo. Deliberately
  obfuscated pickles that build the names some other way are reported as unresolved (PP02).
- The allowlist is hand-picked for common PyTorch, NumPy and scikit-learn style files. Many
  legitimate models (scikit-learn estimators, custom classes) will show PP02 until you `--allow`
  their modules.
- Not covered: legacy (pre-1.6) tar-format PyTorch files beyond the first pickle streams,
  HDF5 `.h5` Keras files, TorchScript code, ONNX/GGUF custom ops, and files over 512 MB inside
  zip archives (skipped).
- The safest fix is still a format that cannot run code, such as safetensors, plus
  `torch.load(..., weights_only=True)`.
