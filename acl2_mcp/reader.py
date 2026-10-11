"""Lexer and top-level form reader for ACL2's reader syntax.

The rules follow the ABNF grammar of ACL2's reader syntax in the ACL2
community books (books/kestrel/acl2pl/grammar.abnf), and lexeme kinds
are that grammar's rule names.  Where the grammar and ACL2's reader
differ, this follows the reader (tests/test_reader_vs_acl2.py compares
the two, on SBCL and CCL):

- As in Common Lisp, a token is collected up to a terminator before it
  is classified as a number or a symbol: 1+ and 123abc are symbols, not
  a number followed by a symbol.
- A decimal integer may end with a decimal point: 123. is 123.
- In a string, a backslash escapes any byte, not only " and \\.
- #b, #o, #x and #nR read ratios as well as integers.
- #c may be followed by intertoken space before its list.
- A character literal ends only at a byte in ACL2's
  *acl2-read-character-terminators*, which doesn't include Return, and
  has no escapes (ACL2's acl2-character-reader).
- #u and #d read an object, so intertoken space may follow them; #u
  takes a sign and ratios.  #d needs a double-float (1.5, not 1 or 1.).
- #f reads bytes for as long as they can continue the number, so
  #f1.5abc is #f1.5 followed by the symbol abc.
- A comma outside a backquote, and ",.", are errors (ACL2's comma
  reader).
- A #n# label must be defined by #n= earlier in the same top-level
  form, and only once; labels are numbers, so #001= defines #1#.

The input is bytes (0-255), as ACL2 reads it: ACL2 source is
ISO-8859-1, and text sent to ACL2 as UTF-8 reaches its reader as the
UTF-8 bytes.

ReadError covers reader errors and what ACL2 rejects right after
reading (bad-lisp-objectp): floats such as 1.5 (except in a form that
a feature conditional skips, where the reader makes no objects),
vectors #(...), and so on.  #Y and #Z (serialized objects) aren't
supported.
"""

import re
from collections.abc import Set
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Syntax:
    """What differs between host Lisps' readers."""

    name: str
    whitespace: frozenset[int]
    # Whether #c(n), with one number, is read (as n)
    complex_of_one: bool = False


# Tab, Newline, Page, Return, Space
SBCL = Syntax("sbcl", frozenset(b"\t\n\f\r "))

# From grammar.abnf's Note 2, which says this still needs to be verified
# by file-based testing: Space, all bytes 0-31 except Backspace, and
# NBSP (160).
CCL = Syntax("ccl", frozenset(set(range(32)) - {8} | {32, 160}),
             complex_of_one=True)

_TERMINATING_MACRO = frozenset(b"\"'(),;`")
_INVALID = frozenset({8, 127})  # Backspace, Rubout

# ACL2's *acl2-read-character-terminators*, for every host Lisp: unlike
# token terminators, these don't include Return (13)
_CHAR_TERMINATORS = frozenset(b"\t\n\f \"'();`,")

_NAMED_CHARACTERS = frozenset(
    [b"space", b"tab", b"newline", b"page", b"rubout", b"return"])

# Upcasing of unescaped symbol constituents: ASCII, and ISO-8859-1
# letters 224-246 and 248-254
_UPCASE = bytes(
    b - 32 if (97 <= b <= 122 or 224 <= b <= 246 or 248 <= b <= 254) else b
    for b in range(256))


class ReadError(ValueError):
    """Input that ACL2's reader rejects, or that ends before a form does.

    KIND is "syntax"; "incomplete" when the input ends inside a form,
    string or comment; "object" for something the reader reads but ACL2
    rejects as an object (such as a float), except in raw mode; or
    "unsupported" for syntax ACL2 reads but this module doesn't (#Y and
    #Z, and objects that only raw mode accepts, such as vectors).
    """

    def __init__(self, message: str, position: int, data: bytes,
                 kind: str = "syntax") -> None:
        self.message = message
        self.position = position
        self.line = data.count(b"\n", 0, position) + 1
        self.column = position - (data.rfind(b"\n", 0, position) + 1) + 1
        self.kind = kind
        super().__init__(f"{message} (line {self.line}, column {self.column})")

    @property
    def incomplete(self) -> bool:
        return self.kind == "incomplete"


@dataclass(frozen=True)
class Lexeme:
    """A token, whitespace, or comment: DATA[START:END]."""

    kind: str
    start: int
    end: int


@dataclass(frozen=True)
class Form:
    """A top-level form: DATA[START:END], with no surrounding space.

    KIND is "s-expression"; "keyword" for a keyword symbol, which ACL2
    reads as a keyword command that reads arguments after it; "skipped"
    for a feature conditional (#+ or #-) whose form the reader skips,
    so that it reads the next form instead; or "conditional" for a
    feature conditional that wasn't evaluated (no features were given).
    """

    kind: str
    start: int
    end: int


_DECIMAL_INTEGER = re.compile(rb"[+-]?[0-9]+\.?")
_RATIO = re.compile(rb"[+-]?[0-9]+/[0-9]+")
_FLOAT = re.compile(
    rb"[+-]?(?:[0-9]*\.[0-9]+(?:[esfdl][+-]?[0-9]+)?"
    rb"|[0-9]+(?:\.[0-9]*)?[esfdl][+-]?[0-9]+)", re.IGNORECASE)
_RADIX_KINDS = {ord("b"): (2, "binary-integer"),
                ord("o"): (8, "octal-integer"),
                ord("x"): (16, "hex-integer")}

_NUMBER_KINDS = frozenset([
    "decimal-integer", "ratio", "binary-integer", "octal-integer",
    "hex-integer", "radix-integer", "complex-rational", "sharp-u-number",
    "sharp-d-float", "sharp-f-float"])
# Lexeme kinds that are complete s-expressions
_ATOM_KINDS = _NUMBER_KINDS | frozenset([
    "character-literal", "string-literal", "fancy-string", "symbol-token",
    "sharp-sharp", "sharp-atsign"])
# Prefixes that take one s-expression, and ones that take two
# Prefixes that take one s-expression (#+, #- and #! take two)
_ONE_ARG_PREFIXES = frozenset([
    "single-quote", "backquote-char", "comma-char", "comma-atsign",
    "sharp-quote-prefix", "sharp-dot-prefix", "sharp-equal"])
_SPACE_KINDS = frozenset(["whitespace", "line-comment", "block-comment"])


class _Lexer:
    def __init__(self, data: bytes, syntax: Syntax) -> None:
        self.data = data
        self.n = len(data)
        self.whitespace = syntax.whitespace
        self.syntax = syntax

    def error(self, message: str, position: int,
              incomplete: bool = False, kind: str = "syntax") -> ReadError:
        return ReadError(message, position, self.data,
                         "incomplete" if incomplete else kind)

    def is_terminator(self, byte: int) -> bool:
        return byte in self.whitespace or byte in _TERMINATING_MACRO

    def lexemes(self) -> list[Lexeme]:
        result = []
        i = 0
        while i < self.n:
            lexeme = self.lexeme(i)
            result.append(lexeme)
            i = lexeme.end
        return result

    def lexeme(self, i: int) -> Lexeme:
        data, b = self.data, self.data[i]
        if b in self.whitespace:
            j = i + 1
            while j < self.n and data[j] in self.whitespace:
                j += 1
            return Lexeme("whitespace", i, j)
        if b == ord(";"):
            j = data.find(b"\n", i)
            return Lexeme("line-comment", i, self.n if j < 0 else j)
        if b == ord('"'):
            return self.string_literal(i)
        single = {ord("("): "open-paren", ord(")"): "close-paren",
                  ord("'"): "single-quote", ord("`"): "backquote-char"}
        if b in single:
            return Lexeme(single[b], i, i + 1)
        if b == ord(","):
            if data[i + 1:i + 2] == b"@":
                return Lexeme("comma-atsign", i, i + 2)
            if data[i + 1:i + 2] == b".":
                raise self.error(",. is not allowed in ACL2", i)
            return Lexeme("comma-char", i, i + 1)
        if b == ord("#"):
            return self.sharp(i)
        return self.token_lexeme(i)

    def string_literal(self, i: int) -> Lexeme:
        j = i + 1
        while j < self.n:
            b = self.data[j]
            if b == ord("\\"):
                j += 2
            elif b == ord('"'):
                return Lexeme("string-literal", i, j + 1)
            else:
                j += 1
        raise self.error("unterminated string", i, incomplete=True)

    def token_end(self, i: int) -> tuple[int, bool]:
        """Collect a token's bytes from I up to a terminator.

        Returns the index after the token and whether it has escapes.
        A # inside a token is a constituent.
        """
        data, j, escaped = self.data, i, False
        while j < self.n:
            b = data[j]
            if b == ord("\\"):
                if j + 1 >= self.n:
                    raise self.error("input ends after \\", j, incomplete=True)
                j += 2
                escaped = True
            elif b == ord("|"):
                k = j + 1
                while True:
                    if k >= self.n:
                        raise self.error("unterminated |...|", j,
                                         incomplete=True)
                    if data[k] == ord("\\"):
                        k += 2
                    elif data[k] == ord("|"):
                        break
                    else:
                        k += 1
                j = k + 1
                escaped = True
            elif self.is_terminator(b):
                break
            elif b in _INVALID:
                raise self.error(f"invalid character (byte {b})", j)
            else:
                j += 1
        return j, escaped

    def token_lexeme(self, i: int) -> Lexeme:
        """A symbol, a number (or a float, which only #d accepts), or a
        dot."""
        j, escaped = self.token_end(i)
        text = self.data[i:j]
        if not escaped:
            if text == b".":
                return Lexeme("dot", i, j)
            if text.strip(b".") == b"":
                raise self.error("a token of only dots", i)
            if _DECIMAL_INTEGER.fullmatch(text):
                return Lexeme("decimal-integer", i, j)
            if _RATIO.fullmatch(text):
                if not text.split(b"/")[1].strip(b"0"):
                    raise self.error("ratio with a zero denominator", i)
                return Lexeme("ratio", i, j)
            if _FLOAT.fullmatch(text):
                return Lexeme("float", i, j)
        return Lexeme("symbol-token", i, j)

    def sharp(self, i: int) -> Lexeme:
        data = self.data
        if i + 1 >= self.n:
            raise self.error("input ends after #", i, incomplete=True)
        d = data[i + 1]
        lower = d | 0x20 if 65 <= d <= 90 else d
        if d == ord("|"):
            return self.block_comment(i)
        if d == ord("\\"):
            return self.character_literal(i)
        if d == ord("{"):
            return self.fancy_string(i)
        prefixes = {ord("'"): "sharp-quote-prefix", ord("!"): "sharp-bang-prefix",
                    ord("+"): "sharp-plus-prefix", ord("-"): "sharp-minus-prefix"}
        if d in prefixes:
            return Lexeme(prefixes[d], i, i + 2)
        if d == ord("."):
            # ACL2's sharp-dot-read also counts Backspace as whitespace
            if i + 2 < self.n and (data[i + 2] in self.whitespace
                                   or data[i + 2] == 8):
                raise self.error("whitespace after #.", i)
            return Lexeme("sharp-dot-prefix", i, i + 2)
        if d == ord("@"):
            k = i + 2
            while k < self.n and data[k] in b"0123456789":
                k += 1
            if k == i + 2 or data[k:k + 1] != b"#":
                raise self.error("#@ must be followed by digits and #", i)
            return Lexeme("sharp-atsign", i, k + 1)
        if lower in _RADIX_KINDS:
            base, kind = _RADIX_KINDS[lower]
            return self.radix_number(i, i + 2, base, kind)
        if lower == ord("c"):
            return self.complex_rational(i)
        if lower == ord("u"):
            return self.sharp_u(i)
        if lower == ord("d"):
            return self.sharp_d(i)
        if lower == ord("f"):
            return self.sharp_f(i)
        if ord("0") <= d <= ord("9"):
            k = i + 1
            while k < self.n and data[k] in b"0123456789":
                k += 1
            if k >= self.n:
                raise self.error("input ends after #n", i, incomplete=True)
            if data[k] == ord("="):
                return Lexeme("sharp-equal", i, k + 1)
            if data[k] == ord("#"):
                return Lexeme("sharp-sharp", i, k + 1)
            if data[k] in b"rR":
                base = int(data[i + 1:k])
                if not 2 <= base <= 36:
                    raise self.error(f"radix {base} is not between 2 and 36", i)
                return self.radix_number(i, k + 1, base, "radix-integer")
        if lower in (ord("y"), ord("z")):
            raise self.error(f"#{chr(d)} (a serialized object) is not supported",
                             i, kind="unsupported")
        if lower in b"(*:aps":
            # Common Lisp objects that ACL2 rejects, except in raw mode
            raise self.error(f"#{chr(d)} is not supported by ACL2's reader",
                             i, kind="unsupported")
        raise self.error(f"#{chr(d)} is not supported by ACL2's reader", i)

    def radix_number(self, i: int, start: int, base: int, kind: str) -> Lexeme:
        j, escaped = self.token_end(start)
        text = self.data[start:j]
        digits = "0123456789abcdefghijklmnopqrstuvwxyz"[:base]
        m = re.fullmatch(rb"[+-]?([0-9a-z]+)(?:/([0-9a-z]+))?", text,
                         re.IGNORECASE)
        if (escaped or not m
                or any(chr(c).lower() not in digits
                       for part in m.groups() if part for c in part)):
            raise self.error(f"bad base-{base} number", i)
        if m.group(2) is not None and not m.group(2).strip(b"0"):
            raise self.error("ratio with a zero denominator", i)
        return Lexeme(kind, i, j)

    def complex_rational(self, i: int) -> Lexeme:
        """#c(real imag), where real and imag are integers or ratios (on
        CCL, imag may be left out)."""
        k = self.skip_space(i + 2)
        if self.data[k:k + 1] != b"(":
            raise self.error("#c must be followed by a list", i,
                             incomplete=k >= self.n)
        k = self.skip_space(k + 1)
        for n in range(2):
            if n == 1 and self.syntax.complex_of_one and self.data[k:k + 1] == b")":
                break
            j, escaped = self.token_end(k)
            text = self.data[k:j]
            if escaped or not (_DECIMAL_INTEGER.fullmatch(text)
                               or _RATIO.fullmatch(text)):
                raise self.error("#c needs two rational numbers", i,
                                 incomplete=k >= self.n)
            k = self.skip_space(j)
        if self.data[k:k + 1] != b")":
            raise self.error("#c needs two rational numbers", i,
                             incomplete=k >= self.n)
        return Lexeme("complex-rational", i, k + 1)

    def object_after(self, i: int) -> Lexeme:
        """The token after the two-byte prefix at I and any intertoken
        space, for ACL2 readers that call read there."""
        k = self.skip_space(i + 2)
        if k >= self.n:
            raise self.error(f"input ends after {self.prefix(i)}", i,
                             incomplete=True)
        return self.lexeme(k)

    def prefix(self, i: int) -> str:
        return self.data[i:i + 2].decode("latin-1")

    def sharp_u(self, i: int) -> Lexeme:
        """#u, as ACL2's sharp-u-read: it reads an object, which must be a
        number or a symbol whose name without underscores is a number
        (B, O or X first: in that base)."""
        token = self.object_after(i)
        if token.kind == "sharp-u-number":
            raise self.error("#u inside #u", i)
        if token.kind in _NUMBER_KINDS:
            return Lexeme("sharp-u-number", i, token.end)
        if token.kind == "symbol-token":
            name = _symbol_name(self.data[token.start:token.end])
            digits = name.replace(b"_", b"")
            if digits[:1] in (b"B", b"O", b"X"):
                base = {b"B": 2, b"O": 8, b"X": 16}[digits[:1]]
                m = re.fullmatch(rb"[+-]?([0-9A-Z]+)(?:/([0-9A-Z]+))?",
                                 digits[1:])
                ok = m is not None and all(
                    int(chr(c), 36) < base
                    for part in m.groups() if part for c in part)
            else:
                ok = any(r.fullmatch(digits)
                         for r in (_DECIMAL_INTEGER, _RATIO))
            if ok:
                return Lexeme("sharp-u-number", i, token.end)
        raise self.error("#u must be followed by a number", i)

    def sharp_d(self, i: int) -> Lexeme:
        """#d, as ACL2's sharp-d-read: it reads an object, which must be a
        double-float (exponent marker e or d, if any)."""
        k = self.skip_space(i + 2)
        if k >= self.n:
            raise self.error("input ends after #d", i, incomplete=True)
        if self.is_terminator(self.data[k]) or self.data[k] == ord("#"):
            raise self.error("#d must be followed by a double-float", i)
        token = self.token_lexeme(k)
        text = self.data[token.start:token.end]
        if token.kind != "float" or re.search(rb"[sfl]", text, re.IGNORECASE):
            raise self.error("#d must be followed by a double-float", i)
        return Lexeme("sharp-d-float", i, token.end)

    def sharp_f(self, i: int) -> Lexeme:
        """#f, as ACL2's sharp-f-read, which reads bytes directly:
        [x] [sign] digits [. digits] [exponent], where digits may include
        underscores and may be empty, and it stops at the first byte that
        can't continue the number (not at a token terminator).

        Like ACL2's reader, this fails when the input ends after the
        decimal point or in the exponent (sharp-f-read then unreads :eof).
        """
        data, j = self.data, i + 2
        if j >= self.n:
            raise self.error("input ends after #f", i, incomplete=True)
        hex_digits = data[j] in b"xX"
        if hex_digits:
            j += 1
        digits = b"0123456789abcdefABCDEF" if hex_digits else b"0123456789"
        exponent_markers = b"pP" if hex_digits else b"eE"

        def read_digits(j: int) -> tuple[int, int, bool]:
            """ACL2's read-digits: returns the index after an optional sign
            and digits/underscores, the number of digits, and whether the
            sign is -."""
            negative = False
            if j < self.n and data[j] in b"+-":
                negative = data[j] == ord("-")
                j += 1
            count = 0
            while j < self.n and (data[j] == ord("_") or data[j] in digits):
                count += data[j] != ord("_")
                j += 1
            return j, count, negative

        at_end = self.error("input ends inside #f", i, incomplete=True)
        j, _, _ = read_digits(j)
        if j < self.n and data[j] == ord("."):
            j, _, negative = read_digits(j + 1)
            if negative:
                raise self.error("illegal sign after point in #f", i)
            if j >= self.n:
                raise at_end
        if j < self.n and data[j] in exponent_markers:
            digits = b"0123456789"
            j, count, _ = read_digits(j + 1)
            if count == 0:
                raise self.error("empty exponent in #f", i)
            if j >= self.n:
                raise at_end
        return Lexeme("sharp-f-float", i, j)

    def skip_space(self, k: int) -> int:
        """The index after any whitespace and comments at K."""
        while k < self.n:
            b = self.data[k]
            if (b in self.whitespace or b == ord(";")
                    or self.data[k:k + 2] == b"#|"):
                k = self.lexeme(k).end
            else:
                break
        return k

    def block_comment(self, i: int) -> Lexeme:
        """#| ... |#, nestable (grammar.abnf's rest-of-block-comment)."""
        data, j, depth, state = self.data, i + 2, 1, "normal"
        while j < self.n:
            b = data[j]
            if state == "after-bar" and b == ord("#"):
                depth -= 1
                if depth == 0:
                    return Lexeme("block-comment", i, j + 1)
                state = "normal"
            elif state == "after-hash" and b == ord("|"):
                depth += 1
                state = "normal"
            elif b == ord("|"):
                state = "after-bar"
            elif b == ord("#"):
                state = "after-hash"
            else:
                state = "normal"
            j += 1
        raise self.error("unterminated #| comment", i, incomplete=True)

    def fancy_string(self, i: int) -> Lexeme:
        """#{\"\"\"...\"\"\"} (grammar.abnf's rest-of-fancy-string)."""
        data = self.data
        if data[i + 2:i + 5] != b'"""':
            raise self.error('#{ must be followed by """', i,
                             incomplete=len(data) < i + 5)
        # State: the number of " just seen (up to 3), or 4 after """\
        j, state = i + 5, 0
        while j < self.n:
            b = data[j]
            if state == 3 and b == ord("}"):
                return Lexeme("fancy-string", i, j + 1)
            if b == ord('"'):
                state = 1 if state == 4 else min(state + 1, 3)
            elif b == ord("\\") and state in (3, 4):
                state = 4
            else:
                state = 0
            j += 1
        raise self.error("unterminated #{ string", i, incomplete=True)

    def character_literal(self, i: int) -> Lexeme:
        """#\\ followed by one byte or a named character.

        As in ACL2's acl2-character-reader: the first byte is taken as is,
        then bytes up to one in *acl2-read-character-terminators* (with no
        escapes); more than one byte must name a character.
        """
        if i + 2 >= self.n:
            raise self.error("input ends after #\\", i, incomplete=True)
        j = i + 3
        while j < self.n and self.data[j] not in _CHAR_TERMINATORS:
            j += 1
        name = self.data[i + 2:j]
        if len(name) > 1 and name.lower() not in _NAMED_CHARACTERS:
            raise self.error(f"#\\{name.decode('latin-1')} is not a character",
                             i)
        return Lexeme("character-literal", i, j)


class _Reader:
    def __init__(self, data: bytes, syntax: Syntax,
                 features: Optional[Set[str]], check_objects: bool) -> None:
        self.lexer = _Lexer(data, syntax)
        self.check_objects = check_objects
        self.data = data
        self.tokens = [x for x in self.lexer.lexemes()
                       if x.kind not in _SPACE_KINDS]
        self.features = features
        # The #n= labels defined so far in the current top-level form
        self.labels: set[int] = set()

    def forms(self) -> list[Form]:
        result = []
        k = 0
        while k < len(self.tokens):
            token = self.tokens[k]
            self.labels = set()
            end = self.sexpr(k)
            kind = "s-expression"
            if token.kind in ("sharp-plus-prefix", "sharp-minus-prefix"):
                if self.features is None:
                    kind = "conditional"
                else:
                    wanted = token.kind == "sharp-plus-prefix"
                    if self.feature_true(k + 1) != wanted:
                        kind = "skipped"
            elif (token.kind == "symbol-token" and _symbol_parts(
                    self.data[token.start:token.end])[0] in (b"", b"KEYWORD")):
                kind = "keyword"
            result.append(Form(kind, token.start, self.tokens[end - 1].end))
            k = end
        return result

    def sexpr(self, k: int, backquotes: int = 0,
              suppressed: bool = False) -> int:
        """Index of the token after the s-expression starting at token K,
        inside BACKQUOTES backquotes (less the commas since).

        SUPPRESSED: the s-expression is in a form that a feature
        conditional skips (or may skip, if features weren't given),
        which the reader reads with *read-suppress*, making no objects.
        """
        token = self.tokens[k]
        kind = token.kind
        if kind == "float":
            if not suppressed and self.check_objects:
                raise self.lexer.error("a float, which is not an ACL2 object",
                                       token.start, kind="object")
            return k + 1
        if kind == "sharp-sharp":
            if (not suppressed and int(self.data[token.start + 1:token.end - 1])
                    not in self.labels):
                raise self.lexer.error("undefined label", token.start)
            return k + 1
        if kind == "sharp-equal" and not suppressed:
            label = int(self.data[token.start + 1:token.end - 1])  # #001= is #1=
            if label in self.labels:
                raise self.lexer.error("label defined twice", token.start)
            self.labels.add(label)
        if kind in _ATOM_KINDS:
            return k + 1
        if kind == "open-paren":
            k += 1
            count = 0
            while True:
                if k >= len(self.tokens):
                    raise self.lexer.error("missing )", token.start,
                                           incomplete=True)
                if self.tokens[k].kind == "close-paren":
                    return k + 1
                if self.tokens[k].kind == "dot":
                    if count == 0:
                        raise self.lexer.error("dot at the start of a list",
                                               self.tokens[k].start)
                    k = self.argument(k + 1, self.tokens[k], backquotes,
                                      suppressed)
                    if k >= len(self.tokens):
                        raise self.lexer.error("missing )", token.start,
                                               incomplete=True)
                    if self.tokens[k].kind != "close-paren":
                        raise self.lexer.error("more than one object after dot",
                                               self.tokens[k].start)
                    return k + 1
                k = self.sexpr(k, backquotes, suppressed)
                count += 1
        if kind == "close-paren":
            raise self.lexer.error("unmatched )", token.start)
        if kind == "dot":
            raise self.lexer.error("dot outside a list", token.start)
        if kind == "backquote-char":
            backquotes += 1
        elif kind in ("comma-char", "comma-atsign"):
            if backquotes == 0:
                raise self.lexer.error("comma not inside a backquote",
                                       token.start)
            backquotes -= 1
        if kind in _ONE_ARG_PREFIXES:
            return self.argument(k + 1, token, backquotes, suppressed)
        if kind in ("sharp-plus-prefix", "sharp-minus-prefix"):
            j = self.argument(k + 1, token, backquotes, suppressed)
            skipped = (suppressed or self.features is None
                       or self.feature_true(k + 1)
                       != (kind == "sharp-plus-prefix"))
            return self.argument(j, token, backquotes, skipped)
        if kind == "sharp-bang-prefix":
            return self.argument(
                self.argument(k + 1, token, backquotes, suppressed),
                token, backquotes, suppressed)
        raise AssertionError(f"unexpected lexeme kind {kind}")

    def argument(self, k: int, prefix: Lexeme, backquotes: int,
                 suppressed: bool) -> int:
        """Like sexpr, for the s-expression that PREFIX needs."""
        if k >= len(self.tokens):
            raise self.lexer.error(
                f"input ends before the object after "
                f"{self.data[prefix.start:prefix.end].decode('latin-1')}",
                prefix.start, incomplete=True)
        return self.sexpr(k, backquotes, suppressed)

    def feature_true(self, k: int) -> bool:
        """Evaluate the feature expression starting at token K.

        It is read in the KEYWORD package: SBCL and :SBCL mean :SBCL; a
        package-qualified symbol such as ACL2::SBCL is never a feature.
        """
        assert self.features is not None
        token = self.tokens[k]
        if token.kind == "symbol-token":
            name = _keyword_name(self.data[token.start:token.end])
            return name is not None and name in self.features
        if token.kind != "open-paren" or k + 1 >= len(self.tokens):
            return False
        op_token = self.tokens[k + 1]
        op = (_keyword_name(self.data[op_token.start:op_token.end])
              if op_token.kind == "symbol-token" else None)
        args = []
        j = k + 2
        while self.tokens[j].kind != "close-paren":
            args.append(j)
            j = self.sexpr(j)
        if op == "AND":
            return all(self.feature_true(a) for a in args)
        if op == "OR":
            return any(self.feature_true(a) for a in args)
        if op == "NOT" and len(args) == 1:
            return not self.feature_true(args[0])
        raise self.lexer.error("bad feature expression", token.start)


def _symbol_parts(text: bytes) -> tuple[Optional[bytes], bytes]:
    """The package prefix and name of the symbol token TEXT, as the reader
    sees them: unescaped bytes upcased, escaped ones as they are.  The
    prefix is None if there is none, and b"" for :NAME."""
    package: Optional[bytes] = None
    name = bytearray()
    i = 0
    while i < len(text):
        b = text[i]
        if b == ord("\\"):
            name.append(text[i + 1])
            i += 2
        elif b == ord("|"):
            i += 1
            while text[i] != ord("|"):
                if text[i] == ord("\\"):
                    i += 1
                name.append(text[i])
                i += 1
            i += 1
        elif b == ord(":") and package is None:
            package = bytes(name)
            name = bytearray()
            i += 2 if text[i + 1:i + 2] == b":" else 1
        else:
            name.append(_UPCASE[b])
            i += 1
    return package, bytes(name)


def _symbol_name(text: bytes) -> bytes:
    return _symbol_parts(text)[1]


def _keyword_name(text: bytes) -> Optional[str]:
    """The name of the symbol TEXT if read in the KEYWORD package, or
    None if it names a symbol in another package."""
    package, name = _symbol_parts(text)
    if package not in (None, b"", b"KEYWORD"):
        return None
    return name.decode("latin-1")


def lex(data: bytes, syntax: Syntax = SBCL) -> list[Lexeme]:
    """Split DATA into lexemes: tokens, whitespace and comments.

    Raises ReadError for lexical errors, such as an unterminated string
    or a malformed character literal.  A float is lexed as "float";
    read_forms rejects it where ACL2 would.
    """
    return _Lexer(data, syntax).lexemes()


def read_forms(data: bytes, syntax: Syntax = SBCL,
               features: Optional[Set[str]] = None,
               check_objects: bool = True) -> list[Form]:
    """Split DATA into its top-level forms.

    FEATURES, the names of the host Lisp's *features* (such as "SBCL";
    ACL2's loop adds "ACL2-LOOP-ONLY"), decides top-level feature
    conditionals; if not given, they are left undecided.
    CHECK_OBJECTS: reject what ACL2 rejects after reading, such as
    floats (ACL2's raw mode doesn't).  Raises ReadError for input that
    ACL2's reader rejects, or that ends inside a form.
    """
    return _Reader(data, syntax, features, check_objects).forms()
