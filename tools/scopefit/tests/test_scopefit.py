import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import scopefit as sf  # noqa: E402

EX = os.path.join(ROOT, "examples")
MAP = sf.load_mapping()


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = sf.main(list(args))
    return code, out.getvalue(), err.getvalue()


def tmpfile(text, suffix=".txt"):
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    return path


def analyze(grants_text, calls, kind="auto", public=False):
    k, g = sf.parse_grants(grants_text, kind)
    m, u, gq = sf.resolve_calls(calls, MAP, public)
    return sf.analyze(k, g, m, u, gq)


class TestMapping(unittest.TestCase):
    def test_mapping_size_and_fields(self):
        self.assertGreaterEqual(len(MAP), 40)
        for e in MAP:
            self.assertIn(e["method"], sf.HTTP_METHODS)
            for lv in e["fine"].values():
                self.assertIn(lv, sf.LEVELS)

    def test_mapping_marked_best_effort(self):
        with open(sf.DEFAULT_MAPPING) as fh:
            about = json.load(fh)["_about"]
        self.assertIn("BEST-EFFORT", about)
        self.assertIn("SUBSET", about)

    def test_no_duplicate_entries(self):
        keys = [(e["method"], e["path"]) for e in MAP]
        self.assertEqual(len(keys), len(set(keys)))

    def test_specific_beats_generic(self):
        e = sf.match_endpoint("GET", "/repos/o/r/commits/abc/status", MAP)
        self.assertEqual(e["path"], "/repos/{owner}/{repo}/commits/{ref}/status")
        e = sf.match_endpoint("GET", "/repos/o/r/releases/latest", MAP)
        self.assertEqual(e["path"], "/repos/{owner}/{repo}/releases/latest")

    def test_multi_segment_contents_path(self):
        e = sf.match_endpoint("GET", "/repos/o/r/contents/a/b/c.py", MAP)
        self.assertEqual(e["fine"], {"contents": "read"})

    def test_method_matters(self):
        self.assertEqual(sf.match_endpoint("POST", "/repos/o/r/issues", MAP)["fine"], {"issues": "write"})
        self.assertIsNone(sf.match_endpoint("DELETE", "/repos/o/r/issues", MAP))


class TestNormalize(unittest.TestCase):
    def test_strip_host_query_slash(self):
        self.assertEqual(sf.normalize_path("https://api.github.com/repos/o/r/issues/?state=open"), "/repos/o/r/issues")

    def test_ghes_prefix(self):
        self.assertEqual(sf.normalize_path("https://ghe.example.com/api/v3/user"), "/user")

    def test_relative_and_colon_placeholders(self):
        self.assertEqual(sf.normalize_path("repos/:owner/:repo/pulls"), "/repos/{owner}/{repo}/pulls")

    def test_templatize_unmapped(self):
        self.assertEqual(sf.templatize("/repos/acme/app/traffic/views/123"), "/repos/{owner}/{repo}/traffic/views/{number}")


class TestExtraction(unittest.TestCase):
    def test_endpoint_lines(self):
        calls = sf.parse_endpoint_lines("# c\nGET /user\n\npost /gists\n")
        self.assertEqual([(c["method"], c["url"]) for c in calls], [("GET", "/user"), ("POST", "/gists")])

    def test_endpoint_lines_bad(self):
        with self.assertRaises(sf.ScopefitError):
            sf.parse_endpoint_lines("FETCH /user")

    def test_curl_parsing(self):
        r = sf.parse_command_string("curl -s -X PATCH -H 'Accept: x' https://api.github.com/repos/o/r/issues/3")
        self.assertEqual(r, [("PATCH", "https://api.github.com/repos/o/r/issues/3")])

    def test_curl_data_implies_post(self):
        r = sf.parse_command_string("curl -d '{}' https://api.github.com/repos/o/r/issues")
        self.assertEqual(r[0][0], "POST")

    def test_curl_ignores_non_github(self):
        self.assertEqual(sf.parse_command_string("curl https://example.com/x"), [])

    def test_gh_api_parsing_chain(self):
        r = sf.parse_command_string("cd x && gh api repos/o/r/pulls/7 --jq .sha; gh api -X DELETE /repos/o/r/releases/9")
        self.assertEqual(r, [("GET", "repos/o/r/pulls/7"), ("DELETE", "/repos/o/r/releases/9")])

    def test_gh_api_fields_imply_post_and_graphql(self):
        r = sf.parse_command_string("gh api repos/o/r/issues -f title=x")
        self.assertEqual(r, [("POST", "repos/o/r/issues")])
        self.assertEqual(sf.parse_command_string("gh api graphql -f query=q"), [("POST", "graphql")])

    def test_openai_tool_calls(self):
        rec = {"role": "assistant", "tool_calls": [{"function": {"name": "http", "arguments": json.dumps({"method": "get", "url": "https://api.github.com/user"})}}]}
        calls = sf.parse_transcript_text(json.dumps(rec))
        self.assertEqual([(c["method"], c["url"]) for c in calls], [("GET", "https://api.github.com/user")])

    def test_anthropic_tool_use_and_results_ignored(self):
        recs = [
            {"role": "assistant", "content": [{"type": "tool_use", "name": "bash", "input": {"command": "gh api user"}}]},
            {"role": "user", "content": [{"type": "tool_result", "content": "curl https://api.github.com/repos/o/r/hooks"}]},
            {"role": "tool", "content": json.dumps({"url": "https://api.github.com/repos/o/r"})},
        ]
        calls = sf.parse_transcript_text("\n".join(json.dumps(r) for r in recs))
        self.assertEqual([(c["method"], c["url"]) for c in calls], [("GET", "user")])

    def test_generic_tool_event(self):
        rec = {"tool": "github", "args": {"method": "POST", "endpoint": "/repos/o/r/pulls"}}
        calls = sf.parse_transcript_text(json.dumps(rec))
        self.assertEqual(calls[0]["method"], "POST")

    def test_file_path_arg_not_mistaken(self):
        rec = {"tool": "read_file", "args": {"path": "/etc/hosts"}}
        self.assertEqual(sf.parse_transcript_text(json.dumps(rec)), [])

    def test_bad_jsonl(self):
        with self.assertRaises(sf.ScopefitError):
            sf.parse_transcript_text('{"a":1}\nnot json\n')


class TestGrants(unittest.TestCase):
    def test_fine_json(self):
        self.assertEqual(sf.parse_grants('{"contents":"write","Pull requests":"read-only","x":"none"}'),
                         ("fine", {"contents": "write", "pull_requests": "read"}))

    def test_classic_list_and_scopes_key(self):
        self.assertEqual(sf.parse_grants('["repo","read:org"]'), ("classic", {"repo", "read:org"}))
        self.assertEqual(sf.parse_grants('{"scopes":"repo, gist"}'), ("classic", {"repo", "gist"}))

    def test_yamlish_fine_and_classic(self):
        self.assertEqual(sf.parse_grants("Issues: read and write\nmetadata: read\n")[1], {"issues": "write", "metadata": "read"})
        self.assertEqual(sf.parse_grants("- repo\n- read:org\n"), ("classic", {"repo", "read:org"}))
        self.assertEqual(sf.parse_grants("scopes: repo, workflow\n"), ("classic", {"repo", "workflow"}))

    def test_permissions_wrapper(self):
        self.assertEqual(sf.parse_grants('{"permissions":{"issues":"read"}}'), ("fine", {"issues": "read"}))

    def test_bad_level(self):
        with self.assertRaises(sf.ScopefitError):
            sf.parse_grants('{"issues":"superuser"}')

    def test_classic_closure(self):
        c = sf.classic_closure(["repo", "admin:org"])
        for s in ("public_repo", "repo:status", "repo_deployment", "write:org", "read:org"):
            self.assertIn(s, c)
        self.assertNotIn("workflow", c)


class TestAnalysis(unittest.TestCase):
    CALLS = [{"method": "GET", "url": "/repos/o/r/issues"}, {"method": "POST", "url": "/repos/o/r/issues/1/comments"},
             {"method": "GET", "url": "/repos/o/r/pulls/2"}]

    def test_fine_exact_fit(self):
        r = analyze('{"metadata":"read","issues":"write","pull_requests":"read"}', self.CALLS)
        self.assertEqual(r["counts"]["over_granted"], 0)
        self.assertEqual(r["counts"]["missing"], 0)
        self.assertEqual(r["suggested"], {"issues": "write", "metadata": "read", "pull_requests": "read"})

    def test_fine_over_level_and_unused(self):
        r = analyze('{"issues":"write","pull_requests":"write","administration":"write"}', self.CALLS)
        over = {x["permission"]: x for x in r["over_granted"]}
        self.assertEqual(over["pull_requests"]["needed"], "read")
        self.assertIsNone(over["administration"]["needed"])
        self.assertIn("administration:write", [h["grant"] for h in r["high_risk"]])

    def test_fine_missing(self):
        r = analyze('{"issues":"read"}', self.CALLS)
        miss = {x["permission"]: x for x in r["missing"]}
        self.assertEqual(miss["issues"]["needed"], "write")
        self.assertIn("pull_requests", miss)
        self.assertNotIn("metadata", miss)  # implicit with any repo permission

    def test_classic_over_and_broader(self):
        r = analyze('["repo","delete_repo","workflow"]', [{"method": "POST", "url": "/repos/o/r/statuses/abc"}])
        over = {x["scope"]: x for x in r["over_granted"]}
        self.assertIn("broader", over["repo"]["reason"])
        self.assertEqual(over["repo"]["narrower"], ["repo:status"])
        self.assertIn("delete_repo", over)
        self.assertEqual(r["suggested"], ["repo:status"])

    def test_classic_missing_and_implied(self):
        r = analyze('["admin:org"]', [{"method": "GET", "url": "/orgs/acme/members"}, {"method": "POST", "url": "/gists"}])
        self.assertEqual([m["scope"] for m in r["missing"]], ["gist"])
        self.assertEqual(r["counts"]["over_granted"], 1)  # admin:org broader than read:org

    def test_public_repos_mode(self):
        r = analyze('["repo"]', [{"method": "GET", "url": "/repos/o/r/issues"}, {"method": "POST", "url": "/repos/o/r/issues"}], public=True)
        self.assertEqual(r["suggested"], ["public_repo"])

    def test_unmapped_never_guessed(self):
        r = analyze('{"issues":"read"}', [{"method": "GET", "url": "/repos/o/r/traffic/views"}, {"method": "POST", "url": "graphql"}])
        self.assertEqual(r["counts"]["unmapped"], 1)
        self.assertEqual(r["counts"]["graphql"], 1)
        self.assertEqual(r["required_fine"], {})
        self.assertNotIn("fine", r["unmapped"][0])

    def test_minimal_classic(self):
        self.assertEqual(sf.minimal_classic({"repo", "repo:status", "gist"}), {"repo", "gist"})

    def test_policy(self):
        r = {"counts": {"over_granted": 1, "missing": 0}}
        self.assertTrue(sf.policy_failed(r, "over"))
        self.assertFalse(sf.policy_failed(r, "missing"))
        self.assertTrue(sf.policy_failed(r, "any"))
        self.assertFalse(sf.policy_failed(r, "none"))


class TestCLI(unittest.TestCase):
    def test_classic_example_fails(self):
        code, out, _ = run_cli("-g", os.path.join(EX, "classic_overprivileged_scopes.json"), "-c", os.path.join(EX, "agent_transcript.jsonl"))
        self.assertEqual(code, 1)
        self.assertIn("OVER-GRANTED", out)
        self.assertIn("delete_repo", out)
        self.assertIn("/repos/{owner}/{repo}/traffic/views", out)

    def test_tight_example_passes(self):
        for g in ("fine_grained_tight.json", "fine_grained_tight.yaml"):
            code, out, _ = run_cli("-g", os.path.join(EX, g), "-c", os.path.join(EX, "agent_transcript.jsonl"))
            self.assertEqual(code, 0, g)

    def test_endpoints_txt_json_output(self):
        code, out, _ = run_cli("-g", os.path.join(EX, "fine_grained_tight.json"), "-c", os.path.join(EX, "endpoints.txt"), "--json")
        self.assertEqual(code, 0)
        d = json.loads(out)
        self.assertEqual(d["counts"]["mapped"], 6)
        self.assertFalse(d["policy"]["failed"])

    def test_fail_on_modes(self):
        args = ["-g", os.path.join(EX, "fine_grained_tight.json"), "-c", os.path.join(EX, "endpoints_needs_more.txt")]
        self.assertEqual(run_cli(*args, "--fail-on", "missing")[0], 1)
        self.assertEqual(run_cli(*args, "--fail-on", "none")[0], 0)

    def test_errors_exit_2(self):
        self.assertEqual(run_cli("-g", "/nonexistent.json", "-c", os.path.join(EX, "endpoints.txt"))[0], 2)
        p = tmpfile("BOGUS line\n")
        self.assertEqual(run_cli("-g", os.path.join(EX, "fine_grained_tight.json"), "-c", p)[0], 2)
        self.assertEqual(run_cli("--fail-on", "maybe")[0], 2)

    def test_multiple_call_files(self):
        code, out, _ = run_cli("-g", os.path.join(EX, "fine_grained_tight.json"), "-c", os.path.join(EX, "endpoints.txt"),
                               "-c", os.path.join(EX, "endpoints_needs_more.txt"), "--json")
        self.assertEqual(json.loads(out)["counts"]["calls"], 9)


if __name__ == "__main__":
    unittest.main()
