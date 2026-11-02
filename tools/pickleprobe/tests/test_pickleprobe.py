import io, json, os, pickle, shutil, struct, subprocess, sys, tempfile, unittest, zipfile
from collections import OrderedDict
from contextlib import redirect_stdout
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "examples"))
import pickleprobe as pp
import make_examples as mk
CLI = [sys.executable, os.path.join(ROOT, "pickleprobe.py")]


def rules(findings):
    return sorted(f.rule for f in findings)


class Reduce:
    def __init__(self, fn, args):
        self.fn, self.args = fn, args

    def __reduce__(self):
        return (self.fn, self.args)


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d)

    def write(self, name, data):
        p = os.path.join(self.d, name)
        with open(p, "wb") as f:
            f.write(data)
        return p


class TestClassify(unittest.TestCase):
    def test_dangerous(self):
        for m, n in [("os", "system"), ("posix", "system"), ("nt", "system"), ("subprocess", "Popen"),
                     ("builtins", "eval"), ("builtins", "exec"), ("builtins", "getattr"), ("__builtin__", "eval"),
                     ("socket", "socket"), ("runpy", "run_path"), ("operator", "attrgetter"),
                     ("functools", "partial"), ("types", "CodeType"), ("urllib.request", "urlopen"),
                     ("os.path", "join"), ("torch", "load"), ("io", "open"), ("pickle", "loads")]:
            self.assertEqual(pp.classify_import(m, n), "dangerous", (m, n))

    def test_safe(self):
        for m, n in [("collections", "OrderedDict"), ("torch._utils", "_rebuild_tensor_v2"),
                     ("torch", "FloatStorage"), ("numpy.core.multiarray", "_reconstruct"),
                     ("numpy", "dtype"), ("builtins", "set"), ("_codecs", "encode"), ("copyreg", "_reconstructor")]:
            self.assertEqual(pp.classify_import(m, n), "safe", (m, n))

    def test_unknown(self):
        self.assertEqual(pp.classify_import("mylib", "Thing"), "unknown")
        self.assertEqual(pp.classify_import("io", "BytesIO"), "unknown")

    def test_allow_glob(self):
        self.assertEqual(pp.classify_import("mylib.models", "Net", ["mylib.*"]), "safe")


class TestPickleParsing(unittest.TestCase):
    def test_real_reduce_all_protocols(self):
        for proto in range(0, 6):
            data = pickle.dumps(Reduce(os.system, ("echo x",)), protocol=proto)
            imps, err, n = pp.pickle_imports(data)
            self.assertIsNone(err, proto)
            self.assertIn(os.system.__module__, [m for m, _, _ in imps])
            self.assertIn("system", [nm for _, nm, _ in imps])

    def test_stack_global_with_memo_get(self):
        # same callable twice: second reference comes from the memo
        data = pickle.dumps([Reduce(eval, ("1",)), Reduce(eval, ("2",))], protocol=4)
        imps, err, _ = pp.pickle_imports(data)
        self.assertIsNone(err)
        self.assertTrue(all((m, n) == ("builtins", "eval") for m, n, _ in imps))
        self.assertGreaterEqual(len(imps), 1)

    def test_multiple_streams(self):
        data = pickle.dumps({"a": 1}, protocol=2) + mk.glob_pickle("os", "system")
        imps, err, n = pp.pickle_imports(data)
        self.assertEqual(n, 2)
        self.assertIn(("os", "system"), [(m, nm) for m, nm, _ in imps])

    def test_truncated(self):
        imps, err, _ = pp.pickle_imports(mk.glob_pickle("os", "system")[:-2])
        self.assertIsNotNone(err)
        self.assertIn(("os", "system"), [(m, nm) for m, nm, _ in imps])  # still reports what it saw

    def test_plain_data_has_no_imports(self):
        imps, err, _ = pp.pickle_imports(pickle.dumps({"x": [1, 2.0, "s", b"b", None, True]}, protocol=5))
        self.assertEqual(imps, [])
        self.assertIsNone(err)

    def test_never_executes(self):
        flag = tempfile.mktemp()
        data = pickle.dumps(Reduce(open, (flag, "w")), protocol=2)
        pp.pickle_imports(data)
        self.assertFalse(os.path.exists(flag))


class TestScanFile(Base):
    def test_raw_dangerous(self):
        f = pp.scan_file(self.write("m.pkl", mk.glob_pickle("os", "system")))
        self.assertEqual(rules(f), ["PP01", "PP08"])
        self.assertEqual([x for x in f if x.rule == "PP01"][0].severity, "critical")

    def test_unknown_import(self):
        f = pp.scan_file(self.write("m.joblib", mk.glob_pickle("fake_mod", "Klass")))
        self.assertIn("PP02", rules(f))
        f2 = pp.scan_file(self.write("n.joblib", mk.glob_pickle("fake_mod", "Klass")), allow=["fake_mod.*"])
        self.assertNotIn("PP02", rules(f2))

    def test_disguised(self):
        f = pp.scan_file(self.write("weights.safetensors", mk.glob_pickle("subprocess", "run")))
        self.assertIn("PP04", rules(f))
        self.assertIn("PP01", rules(f))
        self.assertNotIn("PP08", rules(f))

    def test_real_safetensors_clean(self):
        self.assertEqual(pp.scan_file(self.write("w.safetensors", struct.pack("<Q", 2) + b"{}")), [])

    def test_zip_disguised(self):
        p = os.path.join(self.d, "w.json")
        mk.torch_zip(p, mk.tensor_pickle())
        self.assertIn("PP04", rules(pp.scan_file(p)))

    def test_torch_zip_clean(self):
        p = os.path.join(self.d, "sd.pt")
        mk.torch_zip(p, mk.tensor_pickle())
        self.assertEqual(rules(pp.scan_file(p)), ["PP08"])

    def test_torch_zip_malicious_and_traversal(self):
        p = os.path.join(self.d, "bad.pt")
        mk.torch_zip(p, mk.glob_pickle("posix", "system"), {"/etc/x": "a", "a/../../b": "b"})
        r = rules(pp.scan_file(p))
        self.assertIn("PP01", r)
        self.assertEqual(r.count("PP06"), 2)

    def test_npy_object(self):
        p = os.path.join(self.d, "o.npy")
        mk.npy(p, "|O", mk.glob_pickle("os", "system"))
        self.assertEqual(rules(pp.scan_file(p)), ["PP01", "PP05"])

    def test_npy_numeric_clean(self):
        p = os.path.join(self.d, "f.npy")
        mk.npy(p, "<f8", b"\x00" * 16)
        self.assertEqual(pp.scan_file(p), [])

    def test_npz_member(self):
        inner = os.path.join(self.d, "i.npy")
        mk.npy(inner, "|O", mk.glob_pickle("builtins", "exec"))
        p = os.path.join(self.d, "a.npz")
        with zipfile.ZipFile(p, "w") as z:
            z.write(inner, "arr_0.npy")
        r = rules(pp.scan_file(p))
        self.assertIn("PP05", r)
        self.assertIn("PP01", r)

    def test_keras_lambda(self):
        p = os.path.join(self.d, "m.keras")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("config.json", json.dumps({"class_name": "Lambda", "config": {"name": "l", "function": ["x"]}}))
        self.assertEqual(rules(pp.scan_file(p)), ["PP07"])

    def test_keras_clean(self):
        p = os.path.join(self.d, "m.keras")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("config.json", json.dumps({"class_name": "Dense", "config": {"name": "d"}}))
        self.assertEqual(pp.scan_file(p), [])

    def test_bad_zip(self):
        self.assertIn("PP03", rules(pp.scan_file(self.write("x.pt", b"PK\x03\x04garbage"))))

    def test_dedupe(self):
        data = pickle.dumps([Reduce(os.system, ("a",)), Reduce(os.system, ("b",))], protocol=2)
        f = pp.scan_file(self.write("d.pkl", data))
        self.assertEqual(rules(f).count("PP01"), 1)

    def test_non_pickle_text_ignored(self):
        self.assertEqual(pp.scan_file(self.write("notes.txt", b"hello")), [])


class TestExamplesAndCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        cls.risky, cls.clean = mk.main(cls.d)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d)

    def run_cli(self, *args):
        return subprocess.run(CLI + list(args), capture_output=True, text=True)

    def test_risky_covers_all_rules(self):
        n, f = pp.scan([self.risky])
        self.assertEqual(n, 8)
        self.assertEqual(set(rules(f)), set(pp.RULES))

    def test_clean_only_info(self):
        n, f = pp.scan([self.clean])
        self.assertTrue(all(x.severity == "info" for x in f))

    def test_exit_codes(self):
        self.assertEqual(self.run_cli(self.risky).returncode, 1)
        self.assertEqual(self.run_cli(self.clean).returncode, 0)
        self.assertEqual(self.run_cli(self.risky, "--fail-on", "none").returncode, 0)
        self.assertEqual(self.run_cli(self.clean, "--fail-on", "info").returncode, 1)
        self.assertEqual(self.run_cli(os.path.join(self.d, "missing")).returncode, 2)

    def test_json(self):
        r = self.run_cli(self.risky, "--json", "--min-severity", "critical")
        doc = json.loads(r.stdout)
        self.assertEqual(doc["files_scanned"], 8)
        self.assertTrue(doc["findings"])
        self.assertTrue(all(x["severity"] == "critical" for x in doc["findings"]))

    def test_sarif(self):
        doc = json.loads(self.run_cli(self.risky, "--sarif").stdout)
        self.assertEqual(doc["version"], "2.1.0")
        self.assertTrue(doc["runs"][0]["results"])

    def test_text_summary(self):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = pp.main([self.clean])
        self.assertEqual(rc, 0)
        self.assertIn("4 file(s) scanned", out.getvalue())

    def test_all_files_flag(self):
        p = os.path.join(self.d, "odd.weird")
        with open(p, "wb") as f:
            f.write(mk.glob_pickle("os", "system"))
        n1, _ = pp.scan([self.d])
        n2, f2 = pp.scan([self.d], all_files=True)
        self.assertGreater(n2, n1)
        os.remove(p)


if __name__ == "__main__":
    unittest.main()
