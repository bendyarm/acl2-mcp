"""Compare acl2_mcp.reader with ACL2's own reader.

ACL2 runs once, in batch, and reads each test input in raw Lisp the way
its loop reads input: with *acl2-readtable*, package "ACL2",
:acl2-loop-only in *features*, and the bad-lisp-objectp check.  It
reports where each top-level form ends (read-preserving-whitespace, so
that a whitespace-terminated token's end isn't moved past the space), or
that reading failed.  The Python reader must find the same form ends,
and must fail on the same inputs.

Test inputs: the SNIPPETS below; books/kestrel/acl2pl/reader-tests.lisp;
and the cases in books/kestrel/acl2pl/*.tests (;test-type negative cases
must fail to read).
"""

import re
import subprocess
from pathlib import Path
from typing import Optional

import pytest

from acl2_mcp.reader import CCL, SBCL, ReadError, Syntax, read_forms

# Inputs that the Python reader accepts but ACL2 rejects, because they
# depend on ACL2's world: packages that don't exist
WORLD_DEPENDENT = {"#!nopkg x", "nopkg::x"}

# Inputs in ASCII; each is read as a whole
SNIPPETS = [
    # Tokens: collected up to a terminator, then a number or a symbol
    "(1+ x)", "123abc", "1\\23", "1.5", ".5", "1e3", "123.", "-7.", "+1",
    "1/2", "-3/4", "1/0", "+", "-", "a..b", "|..|", "..", "a|b c|d",
    # Radix numbers
    "#x1/2", "#b-101", "#o17", "#36rZz", "#x1g", "#2r102", "#37r1", "#X1F",
    # Complex rationals
    "#c(1 2)", "#c (1 2)", "#c(1/2 -3)", "#C( 1 2 )", "#c(1 #|x|# 2)",
    "#c(1.5 2)", "#c(1)",
    # Lists and dots
    "(a . b)", "(a b . c)", "(a . b c)", "( . a)", "(a .)", "(a", ")",
    "(a))", "(a .b)", "()",
    # Strings
    '"a\\b"', '"a\\"b"', '"abc', '"a;b(c"',
    # Character literals
    "#\\a", "#\\Space", "#\\space", "#\\SPACE", "#\\Spacex", "#\\(", "#\\)",
    "#\\;", "#\\\\", "#\\|", "#\\a#b", "(#\\a)", "#\\Linefeed", "#\\a\rb",
    "#\\ab", "#\\", "#\\Tab", "#\\Page", "#\\Rubout", "#\\Return",
    "#\\Newline", "(#\\( #\\))",
    # Comments
    "; c\n(a)", "#| x |# (a)", "#| #| nested |# |# a", "#||#a", "#|||#a",
    "#| unterminated", "(a ; c\n b)", "#|#|#", "#| a |# |#",
    # Fancy strings
    '#{"""abc"""}', '#{"""a"""\\}b"""}', '#{""""""}', '#{"""a""""}',
    '#{"a"}', '#{"""unterminated',
    # #u
    "#u1_000", "#u 1_000", "#u-5", "#ux1_F", "#ub1_01", "#u|1_000|",
    "#uabc", "#u(1)", "#u1/2", "#u1.5", "#u#x10",
    # #f (ACL2's reader fails if the input ends inside the fraction or
    # the exponent)
    "#f1.5", "#f1.5 ", "#f15", "#f1e2", "#f1e2 ", "#fx1.8p3 ", "#f1.5abc", "#fx1.8p3", "#f1.-5", "#f-0.5e-2", "#fabc",
    "#f1_000.5", "#f1e",
    # #d
    "#d1.5", "#d 2.5d0", "#d1", "#d1.", "#d1.5f0", "#d.5", "#d1e5",
    # #. and #!
    "#. x", "#!acl2 (a)", '#!"ACL2" b', "#!nopkg x",
    # Feature conditionals
    "#+sbcl a b", "#-sbcl a b", "#+(or sbcl ccl) a", "#+(and) a b",
    "#+(or) a b", "#+acl2-loop-only a b", "#-acl2-loop-only a b",
    "#+acl2::sbcl a b", "(#+nope a b)", "#+(not ccl) a",
    # A skipped form makes no objects, so a float there is fine
    "#+nope 1.5 a", "(#-sbcl 1.5d0 b)", "#+sbcl 1.5", "(#+nope (#1# x) y)",
    # #n= and #n#
    "(#1=a #1#)", "(#1# a)", "(#1=a #1=b)", "(#1=a) (#1#)",
    # Quote, backquote, comma
    "'a", "' a", "'", "'(a b)", "#'car", "`(a ,b ,@c)", "(a ,b)", ",a",
    "`,a", "``(a ,,b)", "`(a ,.b)",
    # Keywords and packages
    ":pe foo", "keyword::x", "acl2::x", "nopkg::x",
    # Unsupported or rejected objects
    "#(1 2)", "#*101", "#:foo", "#<foo>", "# a", "#",
]

LISP = r'''
(include-book "kestrel/acl2pl/sharp-dot-test-consts" :dir :system)
:q
(in-package "ACL2")
(pushnew :acl2-loop-only *features*)
(defun mcp-form-ends (stream)
  ;; acl2-reader-error calls (clear-input), which must not eat this script
  (let ((*standard-input* (make-string-input-stream ""))
        (*readtable* *acl2-readtable*)
        (*package* (find-package "ACL2"))
        (eof (list :eof))
        (ends nil))
    (handler-case
        (loop for form = (read-preserving-whitespace stream nil eof)
              until (eq form eof)
              do (when (bad-lisp-objectp form) (error "bad object"))
                 (push (file-position stream) ends)
              finally (return (cons :ok (reverse ends))))
      (error () (cons :error (reverse ends))))))
(defun mcp-report (id result)
  (format t "~&@@RESULT ~a ~a~{ ~d~}~%" id (car result) (cdr result)))
(defun mcp-report-string (id string)
  (mcp-report id (with-input-from-string (s string) (mcp-form-ends s))))
(defun mcp-report-file (id path)
  (format t "~&@@FILE ~a ~a~%" id path)
  (mcp-report id (with-open-file (s path :external-format :iso-8859-1)
                   (mcp-form-ends s))))
(defvar *mcp-books* (cdr (assoc :system (project-dir-alist (w *the-live-state*)))))
(format t "~&@@FEATURES~{ ~a~}~%" *features*)
(format t "~&@@BOOKS ~a~%" *mcp-books*)
'''


def lisp_string(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def cases_in_tests_file(path: Path) -> list[tuple[str, str, str]]:
    """The (id, type, body) cases of a .tests file: blocks that start
    with ;test-type and ;test-id lines."""
    cases = []
    for block in re.split(r"\n(?=;test-type )", path.read_text("latin-1")):
        m = re.match(r";test-type (\w+)\n;test-id (\S+)\n(.*)", block, re.S)
        if m:
            cases.append((m.group(2), m.group(1), m.group(3)))
    return cases


@pytest.fixture(scope="module")
def acl2_results() -> dict[str, object]:
    """Run ACL2 once on all the inputs; return its reports."""
    first = subprocess.run(["acl2"], input=LISP.encode(), capture_output=True,
                           timeout=300).stdout.decode("latin-1")
    books = Path(re.search(r"@@BOOKS (.*)", first).group(1))  # type: ignore[union-attr]
    on_sbcl = "SBCL" in re.search(r"@@FEATURES(.*)", first).group(1).split()  # type: ignore[union-attr]
    acl2pl = books / "kestrel" / "acl2pl"
    inputs: dict[str, tuple[bytes, Optional[str]]] = {}
    script = [LISP]
    for i, snippet in enumerate(SNIPPETS):
        inputs[f"s{i}"] = (snippet.encode("latin-1"), None)
        script.append(f"(mcp-report-string \"s{i}\" {lisp_string(snippet)})")
    reader_tests = acl2pl / "reader-tests.lisp"
    if reader_tests.exists() and on_sbcl:  # it is SBCL-only
        inputs["reader-tests"] = (reader_tests.read_bytes(), None)
        script.append(f'(mcp-report-file "reader-tests" "{reader_tests}")')
    for tests in sorted(acl2pl.glob("*.tests")):
        for case_id, case_type, body in cases_in_tests_file(tests):
            inputs[case_id] = (body.encode("latin-1"), case_type)
            script.append(f"(mcp-report-string \"{case_id}\" {lisp_string(body)})")
    out = subprocess.run(["acl2"], input="\n".join(script).encode("latin-1"),
                         capture_output=True, timeout=600).stdout.decode("latin-1")
    features = set(re.search(r"@@FEATURES(.*)", out).group(1).split())  # type: ignore[union-attr]
    reports = {}
    for m in re.finditer(r"@@RESULT (\S+) (OK|ERROR)((?: \d+)*)", out):
        reports[m.group(1)] = (m.group(2), [int(x) for x in m.group(3).split()])
    return {"inputs": inputs, "features": features, "reports": reports,
            "syntax": SBCL if on_sbcl else CCL}


def python_result(data: bytes, features: set[str],
                  syntax: Syntax) -> tuple[str, list[int]]:
    try:
        forms = read_forms(data, syntax, features)
    except ReadError:
        return "ERROR", []
    return "OK", [f.end for f in forms if f.kind != "skipped"]


def test_python_reader_matches_acl2(acl2_results: dict) -> None:
    inputs, features, reports = (acl2_results["inputs"],
                                 acl2_results["features"],
                                 acl2_results["reports"])
    assert set(reports) == set(inputs), "ACL2 didn't report on every input"
    mismatches = []
    for name, (data, case_type) in inputs.items():
        acl2_status, acl2_ends = reports[name]
        status, ends = python_result(data, features, acl2_results["syntax"])
        expected = (acl2_status, acl2_ends if acl2_status == "OK" else [])
        if data.decode("latin-1") in WORLD_DEPENDENT:
            assert (acl2_status, status) == ("ERROR", "OK"), name
            continue
        if (status, ends) != expected:
            mismatches.append(f"{name} {data[:60]!r}: ACL2 {expected}, "
                              f"Python {(status, ends)}")
        if case_type == "negative":
            assert acl2_status == "ERROR", f"{name} should fail in ACL2"
    assert not mismatches, "\n".join(mismatches)
