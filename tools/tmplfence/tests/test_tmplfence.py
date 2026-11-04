#!/usr/bin/env python3
"""Tests for tmplfence."""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import tmplfence as tf  # noqa: E402

EX = os.path.join(ROOT, "examples")


def run_main(argv):
    buf = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(err):
        code = tf.main(argv)
    return code, buf.getvalue(), err.getvalue()


def unit(text, role="", source="t", template_id="t1", var_name="", kind="template"):
    return tf.TemplateUnit(
        source=source, text=text, template_id=template_id,
        role=role, kind=kind, var_name=var_name,
    )


class TestNameHeuristics(unittest.TestCase):
    def test_userish_exact(self):
        self.assertTrue(tf.is_userish("user_input"))
        self.assertTrue(tf.is_userish("query"))
        self.assertTrue(tf.is_userish("customer_message"))

    def test_userish_prefix(self):
        self.assertTrue(tf.is_userish("user_foo"))
        self.assertTrue(tf.is_userish("human_turn"))

    def test_system_message_not_userish(self):
        self.assertFalse(tf.is_userish("system_message"))
        self.assertFalse(tf.is_userish("developer_prompt"))

    def test_systemish(self):
        self.assertTrue(tf.is_systemish_name("system_prompt"))
        self.assertTrue(tf.is_systemish_name("developer_message"))
        self.assertFalse(tf.is_systemish_name("user_input"))

    def test_broad(self):
        self.assertTrue(tf.is_broad("query"))
        self.assertTrue(tf.is_broad("input"))
        self.assertFalse(tf.is_broad("user_email"))


class TestPlaceholderExtract(unittest.TestCase):
    def test_jinja(self):
        ph = list(tf._extract_placeholders("Hello {{ user_input }}!"))
        self.assertEqual(ph[0][0], "user_input")
        self.assertEqual(ph[0][5], "jinja")

    def test_triple(self):
        ph = list(tf._extract_placeholders("X {{{ customer_message }}} Y"))
        names = [p[0] for p in ph]
        self.assertIn("customer_message", names)
        styles = {p[0]: p[5] for p in ph}
        self.assertEqual(styles["customer_message"], "triple")

    def test_filter(self):
        ph = list(tf._extract_placeholders("{{ query | safe }}"))
        self.assertEqual(ph[0][0], "query")
        self.assertIn("safe", ph[0][4])

    def test_simple_brace(self):
        ph = list(tf._extract_placeholders("Context: {user_input}"))
        self.assertEqual(ph[0][0], "user_input")
        self.assertEqual(ph[0][5], "brace")


class TestClassifyTM01(unittest.TestCase):
    def test_user_in_system_role(self):
        u = unit("Notes: {{ user_input }}", role="system")
        rules = {f.rule for f in tf.classify_unit(u)}
        self.assertIn("TM01", rules)

    def test_user_role_ok(self):
        u = unit("{{ user_message }}", role="user")
        rules = {f.rule for f in tf.classify_unit(u)}
        self.assertNotIn("TM01", rules)

    def test_systemish_var_name(self):
        u = unit("See {{ query }}", role="", var_name="system_prompt")
        self.assertIn("TM01", {f.rule for f in tf.classify_unit(u)})


class TestClassifyTM02TM08(unittest.TestCase):
    def test_triple_userish(self):
        u = unit("{{{ user_input }}}", role="system")
        rules = {f.rule for f in tf.classify_unit(u)}
        self.assertIn("TM02", rules)

    def test_safe_filter(self):
        u = unit("{{ query | safe }}", role="system")
        self.assertIn("TM02", {f.rule for f in tf.classify_unit(u)})

    def test_autoescape_off(self):
        u = unit("{% autoescape false %}\nHi {{ user_input }}", role="system")
        self.assertIn("TM02", {f.rule for f in tf.classify_unit(u)})

    def test_triple_non_userish_tm08(self):
        u = unit("{{{ company_name }}}", role="system")
        rules = {f.rule for f in tf.classify_unit(u)}
        self.assertIn("TM08", rules)
        self.assertNotIn("TM02", rules)


class TestClassifyTM03(unittest.TestCase):
    def test_adjacent_system_token(self):
        u = unit("<|system|>\nYou are X.\n{{ user_message }}\n", role="")
        rules = {f.rule for f in tf.classify_unit(u)}
        self.assertIn("TM03", rules)


class TestClassifyTM04TM07(unittest.TestCase):
    def test_dunder_class(self):
        u = unit("{{ ''.__class__.__mro__ }}", role="system")
        self.assertIn("TM04", {f.rule for f in tf.classify_unit(u)})

    def test_attr_filter(self):
        u = unit("{{ user_input | attr('x') }}", role="system")
        self.assertIn("TM04", {f.rule for f in tf.classify_unit(u)})

    def test_jinja_for(self):
        u = unit("{% for x in items %}{{ x }}{% endfor %}", role="system")
        self.assertIn("TM04", {f.rule for f in tf.classify_unit(u)})

    def test_dynamic_include(self):
        u = unit("{% include page %}\nHello", role="system")
        rules = {f.rule for f in tf.classify_unit(u)}
        self.assertIn("TM07", rules)
        self.assertIn("TM04", rules)


class TestClassifyTM06TM09(unittest.TestCase):
    def test_undifferentiated(self):
        u = unit(
            "You are a helpful assistant.\nAlways be kind.\nUser said: {{ user_input }}",
            role="",
        )
        self.assertIn("TM06", {f.rule for f in tf.classify_unit(u)})

    def test_broad_in_system(self):
        u = unit("Context: {{ query }}", role="system")
        self.assertIn("TM09", {f.rule for f in tf.classify_unit(u)})


class TestPythonLoader(unittest.TestCase):
    def test_fstring_tm05(self):
        src = (
            "user_input = 'x'\n"
            "query = 'y'\n"
            "system_prompt = f'You are bot. Ctx: {user_input} q={query}'\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fh:
            fh.write(src)
            path = fh.name
        try:
            units, early = tf.load_units_from_python(path)
            rules = {f.rule for f in early}
            self.assertIn("TM05", rules)
            all_f = tf.classify_all(units, early_findings=early)
            self.assertIn("TM01", {f.rule for f in all_f})
        finally:
            os.unlink(path)

    def test_concat_tm05(self):
        src = "user_input = 'x'\nsystem_message = 'Rules:\\n' + user_input\n"
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fh:
            fh.write(src)
            path = fh.name
        try:
            units, early = tf.load_units_from_python(path)
            self.assertTrue(any(f.rule == "TM05" for f in early))
        finally:
            os.unlink(path)

    def test_safe_separate_roles(self):
        src = (
            "def make(user_message):\n"
            "    system_prompt = 'You are SecureBot. Stay in role.'\n"
            "    return system_prompt, user_message\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fh:
            fh.write(src)
            path = fh.name
        try:
            units, early = tf.load_units_from_python(path)
            findings = tf.classify_all(units, early_findings=early)
            actionable = [f for f in findings if f.rule != "TM10"]
            self.assertEqual(actionable, [])
        finally:
            os.unlink(path)


class TestJSONLoader(unittest.TestCase):
    def test_chat_system_injection(self):
        obj = {
            "messages": [
                {"role": "system", "content": "Policy.\n{{ user_query }}"},
                {"role": "user", "content": "{{ message }}"},
            ]
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(obj, fh)
            path = fh.name
        try:
            units = tf.load_units_from_json(path)
            findings = tf.classify_all(units)
            rules = {f.rule for f in findings}
            self.assertIn("TM01", rules)
            # user-role placeholder alone must not be TM01
            sys_findings = [f for f in findings if f.rule == "TM01"]
            self.assertTrue(all("user_query" in f.placeholder or "user_query" in f.message
                                for f in sys_findings))
        finally:
            os.unlink(path)


class TestCLIExamples(unittest.TestCase):
    def test_list_rules(self):
        code, out, _ = run_main(["--list-rules"])
        self.assertEqual(code, 0)
        self.assertIn("TM01", out)
        self.assertIn("TM10", out)

    def test_no_args(self):
        code, _, _ = run_main([])
        self.assertEqual(code, 2)

    def test_risky_jinja_example(self):
        code, out, _ = run_main([
            os.path.join(EX, "system_prompt.j2"), "--disable", "TM10",
        ])
        self.assertEqual(code, 1)
        self.assertIn("TM01", out)

    def test_clean_jinja_example(self):
        code, out, _ = run_main([
            os.path.join(EX, "clean_system.j2"), "--disable", "TM10",
        ])
        self.assertEqual(code, 0)
        self.assertIn("No prompt-template injection findings", out)

    def test_clean_chat_example(self):
        code, _, _ = run_main([
            os.path.join(EX, "clean_chat.json"), "--disable", "TM10",
        ])
        self.assertEqual(code, 0)

    def test_raw_mustache(self):
        code, out, _ = run_main([
            os.path.join(EX, "system_raw.mustache"), "--disable", "TM10", "TM09",
        ])
        self.assertEqual(code, 1)
        self.assertIn("TM02", out)

    def test_dangerous_jinja(self):
        code, out, _ = run_main([
            os.path.join(EX, "dangerous_jinja.j2"), "--disable", "TM10",
        ])
        self.assertEqual(code, 1)
        self.assertIn("TM04", out)
        self.assertIn("TM07", out)

    def test_build_prompts_py(self):
        code, out, _ = run_main([
            os.path.join(EX, "build_prompts.py"), "--disable", "TM10", "TM09",
        ])
        self.assertEqual(code, 1)
        self.assertIn("TM05", out)

    def test_json_output(self):
        code, out, _ = run_main([
            os.path.join(EX, "system_prompt.j2"), "--json", "--disable", "TM10",
        ])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(data["tool"], "tmplfence")
        self.assertTrue(any(f["rule"] == "TM01" for f in data["findings"]))

    def test_fail_on_none(self):
        code, _, _ = run_main([
            os.path.join(EX, "system_prompt.j2"), "--fail-on", "none", "--disable", "TM10",
        ])
        self.assertEqual(code, 0)

    def test_fail_on_critical(self):
        code, _, _ = run_main([
            os.path.join(EX, "system_prompt.j2"), "--fail-on", "critical", "--disable", "TM10",
        ])
        self.assertEqual(code, 1)

    def test_min_severity_filters(self):
        code, out, _ = run_main([
            os.path.join(EX, "system_prompt.j2"),
            "--min-severity", "critical", "--disable", "TM10", "--json",
        ])
        data = json.loads(out)
        self.assertTrue(all(f["severity"] == "critical" for f in data["findings"]))
        self.assertEqual(code, 1)

    def test_dir_scan(self):
        code, out, _ = run_main([EX, "--disable", "TM10", "--fail-on", "critical"])
        self.assertEqual(code, 1)
        self.assertIn("TM01", out)

    def test_stdin(self):
        old = sys.stdin
        try:
            sys.stdin = io.StringIO(
                "You are a bot.\nUser data: {{ user_input }}\n"
            )
            code, out, _ = run_main(["-", "--disable", "TM10"])
            self.assertEqual(code, 1)
            self.assertIn("TM01", out)
        finally:
            sys.stdin = old


class TestDisable(unittest.TestCase):
    def test_disable_tm01(self):
        u = unit("{{ user_input }}", role="system")
        findings = tf.classify_unit(u, disabled={"TM01", "TM06", "TM09"})
        self.assertFalse(any(f.rule == "TM01" for f in findings))


if __name__ == "__main__":
    unittest.main()
