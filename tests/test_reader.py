"""Tests of acl2_mcp.reader's interface.  Agreement with ACL2's own
reader is tested in test_reader_vs_acl2.py."""

import pytest

from acl2_mcp.reader import CCL, ReadError, lex, read_forms


def kinds(data: bytes) -> list[tuple[str, bytes]]:
    return [(x.kind, data[x.start:x.end]) for x in lex(data)
            if x.kind != "whitespace"]


@pytest.mark.parametrize("data, kind", [
    (b"1+", "symbol-token"),        # a token is classified once it ends
    (b"123abc", "symbol-token"),
    (b"123.", "decimal-integer"),
    (b"-3/4", "ratio"),
    (b"#x1/2", "hex-integer"),
    (b"#36rZz", "radix-integer"),
    (b"#c (1 2)", "complex-rational"),
    (b"#u 1_000", "sharp-u-number"),
    (b"#d1.5", "sharp-d-float"),
    (b"#fx1.8p3 ", "sharp-f-float"),
    (b"#\\Space", "character-literal"),
    (b'"a\\b"', "string-literal"),
    (b'#{"""a"""\\}b"""}', "fancy-string"),
    (b"#| a #| b |# c |#", "block-comment"),
    (b"; comment", "line-comment"),
    (b"#1=", "sharp-equal"),
    (b",@", "comma-atsign"),
])
def test_lexeme_kinds(data: bytes, kind: str) -> None:
    assert kinds(data)[0] == (kind, data.rstrip())


def test_sharp_f_stops_where_the_number_does() -> None:
    assert kinds(b"#f1.5abc") == [("sharp-f-float", b"#f1.5"),
                                  ("symbol-token", b"abc")]


def test_form_spans_and_kinds() -> None:
    data = b"; start\n(defun f (x) x)  :pe f\n#| c |# 'a\n"
    forms = read_forms(data)
    assert [(f.kind, data[f.start:f.end]) for f in forms] == [
        ("s-expression", b"(defun f (x) x)"),
        ("keyword", b":pe"),
        ("s-expression", b"f"),
        ("s-expression", b"'a"),
    ]


def test_feature_conditionals() -> None:
    data = b"#+sbcl a #-sbcl b #+(and sbcl (not ccl)) c #+acl2::sbcl d e"
    assert [f.kind for f in read_forms(data, features={"SBCL"})] == [
        "s-expression", "skipped", "s-expression", "skipped", "s-expression"]
    assert [f.kind for f in read_forms(data)] == [
        "conditional", "conditional", "conditional", "conditional",
        "s-expression"]


@pytest.mark.parametrize("data, incomplete", [
    (b"(a (b)", True),
    (b'"abc', True),
    (b"#| abc", True),
    (b"'", True),
    (b"#\\", True),
    (b"a)", False),
    (b"#\\Spacex", False),
    (b"(a ,b)", False),
    (b"1.5", False),
])
def test_errors(data: bytes, incomplete: bool) -> None:
    with pytest.raises(ReadError) as info:
        read_forms(data)
    assert info.value.incomplete == incomplete


def test_error_position() -> None:
    with pytest.raises(ReadError) as info:
        read_forms(b"(a)\n  (b ,c)")
    assert (info.value.line, info.value.column) == (2, 6)


def test_host_lisp_whitespace() -> None:
    # Byte 160 (NBSP, and the second byte of UTF-8 "à") is a constituent
    # on SBCL but whitespace on CCL
    data = "voilà!".encode()
    assert len(read_forms(data)) == 1
    assert len(read_forms(data, CCL)) == 2
