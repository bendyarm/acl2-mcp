---
name: acl2-doc-lookup
description: Look up ACL2 documentation (aka xdoc) for symbols, functions, macros, and concepts from the official ACL2 online documentation
allowed-tools: WebFetch
---

# ACL2 Documentation Lookup Skill

Use this skill to look up ACL2 documentation for symbols, functions, macros, and concepts.

## URL Pattern

The ACL2 documentation has an SEO-friendly interface that loads quickly, for example:

```
https://acl2.org/doc/index-seo.php?xkey=PACKAGE____SYMBOL
```

Note: The separator between package and symbol is **four underscores** (`____`).

## Common Packages

- `ACL2` - Most built-in functions, macros, and the main part of the Axe toolkit
- `COMMON-LISP` - Common Lisp primitives available in ACL2
- `BUILD` - Build system utilities (cert.pl, depends-on, etc.)
- `FTY` - Data types
- `STD` - Std Utilities, including `Define` and `Defines`
- `STR` - String utilities from Std
- `X86ISA` - x86 model and related functions (x86isa project)
- `X` - x86 specific parts of the Axe toolkit

## Hard-to-Guess Package Mappings

Some symbols are in unexpected packages.  For example:

```lisp
ACL2 !>(symbol-package-name 'symbol-package)
(symbol-package-name 'symbol-package)
"COMMON-LISP"
ACL2 !>(symbol-package-name 'symbol-package-name)
(symbol-package-name 'symbol-package-name)
"ACL2"
```

## How to Look Up Documentation

1. **Determine the package**: Most symbols are in `ACL2`, so if you are not sure, try that.
   Source files have an `in-package` form at the top.  In the REPL, the ACL2 prompt shows
   the current package, so if a symbol is usable in that context, you can see
   its package by calling `symbol-package-name` on it.

2. **Construct the URL**:
   a. Start with the symbol's package name (e.g., `ACL2`)
   b. Append `____` (four underscores) as the package separator
   c. Append the `symbol-name`, applying these rules:
      - If the symbol prints without `|...|` bars, upcase it
      - If the symbol prints with `|...|` bars, preserve its case
      - Keep hyphens as-is
      - Replace each other non-alphanumeric character with `_XX`
        where XX is the two hex digits of its ASCII code, reversed
        (e.g., `*` = 0x2A → `_A2`, `+` = 0x2B → `_B2`, space = 0x20 → `_02`)
   d. Prepend `https://acl2.org/doc/index-seo.php?xkey=`

   Examples:
   - `x86isa` → `ACL2____X86ISA`
   - `*ACL2-exports*` → `ACL2_____A2ACL2-EXPORTS_A2` (note: five underscores — four for `::` and one that begins `_A2`)
   - `Modeling Algorithms in C++ and ACL2` → `RTL____Modeling_02Algorithms_02in_02C_B2_B2_02and_02ACL2` (a `|...|`-escaped symbol created for a documentation topic, so it has lowercase and spaces)

3. **Fetch the page**: Use WebFetch with a prompt to extract the relevant information.

4. **Follow subtopic links**: Documentation pages often link to subtopics with more detail. The link pattern includes `xkey=PACKAGE____SUBTOPIC`.

## Example Usage

To look up documentation for `def-simplified`:

```
WebFetch(
  url: "https://acl2.org/doc/index-seo.php?xkey=ACL2____DEF-SIMPLIFIED",
  prompt: "Show the complete documentation including function signature, parameters, and usage examples. List all subtopics."
)
```

To look up Axe rewriter tools:

```
WebFetch(
  url: "https://acl2.org/doc/index-seo.php?xkey=ACL2____AXE-REWRITERS",
  prompt: "List all available rewriter tools and their descriptions."
)
```

## Tips

- Documentation pages often have subtopics - follow these links for detailed information
- The SEO pages load much faster than the main `https://acl2.org/doc` interface
- When the web doc is sparse, check for comments and read the code in the relevant
  source file in the ACL2 community books source tree `/path/to/acl2/books/`.

## Some Useful Top-Level Topics

- `ACL2____DEFTHM` - Theorem proving
- `ACL2____HINTS` - Proof hints
- `ACL2____BV` - Bitvector operations
- `ACL2____X86ISA` - x86 instruction set architecture model
- `ACL2____AXE` - Axe toolkit overview
- `ACL2____AXE-REWRITERS` - Rewriter tools (def-simplified, rewriter-basic, etc.)
