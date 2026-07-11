# LSQUIC Contributor Guidance

## Scope and sources of truth

This file applies to the whole repository.  A more deeply nested `AGENTS.md`,
if one is added later, overrides it for that subtree.

Before changing code, read the relevant section of `docs/internals.rst`,
and the implementation and tests around the code in
question.  Use the documentation as an architectural map, but verify details
against the current source: the internal document describes an older code
version, and the API reference itself warns that it may lag the public headers.
The current source, public headers, and CMake files are authoritative.

## Repository map and architecture

- `include/` contains the public API.  `include/lsquic.h` is its main entry
  point.
- `src/liblsquic/` contains the library implementation.  The engine owns and
  schedules connections; full connections own streams.  Server connections
  begin as mini connections and may be promoted to full connections.
- QUIC versions and connection types share interfaces but often have separate
  implementations.  Parsing and generation are selected through
  `struct parse_funcs`; gQUIC and IETF QUIC behavior must not be assumed to be
  identical.
- `bin/` contains example clients and servers and is useful for public-API
  usage patterns.
- `tests/` contains assertion-based C unit tests registered through CMake.
- `docs/` contains the Sphinx API, tutorial, development, and internals
  documentation.
- `src/lshpack/` and `src/liblsquic/ls-qpack/` are Git submodules.  Do not edit
  them unless the task explicitly includes the corresponding upstream code.

Performance is a primary design constraint.  In hot paths, preserve allocation
behavior, copy counts, batching, queue and heap complexity, packet coalescing,
and cache-friendly layouts unless a deliberate change is required.  Pay close
attention to connection refcounts and to flags that record queue or heap
membership.

When changing shared protocol behavior, determine which of these dimensions
are relevant and cover them deliberately: client/server, gQUIC/IETF QUIC,
HTTP/non-HTTP, and mini/full connections.

## Worktree hygiene

- Inspect `git status` before editing.  The tree may contain user-owned
  changes, build directories, logs, core files, `.orig` files, and `.rej`
  files.  Preserve them and do not include them in the change.
- Keep patches focused.  Do not perform broad formatting, cleanup, or adjacent
  refactoring unless it is needed for the requested change.
- Use a new task-specific out-of-source build directory; do not reconfigure,
  overwrite, or delete an existing build tree unless it was created for the
  current task.
- Do not commit generated build files or test artifacts.

## Commit messages

- Keep summary and body lines to at most 72 characters.
- For a bug fix, begin the summary with `Fix: `.
- Follow the summary with a blank line and one or two human-readable,
  ASCII-only paragraphs that describe what was fixed and why.  Describe
  how only when it is not obvious from the code.
- Use two spaces after a sentence-ending period when another sentence
  follows on the same line.
- When a commit fixes a GitHub issue, identify it in a final paragraph
  using `Fixes #NNN.`.

## C style

Follow the surrounding file and these project conventions:

- Indent with four spaces.  Put two blank lines between function definitions
  and, generally, between all top-level constructs.
- Do not cuddle control-flow braces.  Function definitions place the return
  type on one line and the left-aligned function name on the next:

  ```c
  static int
  process_packet (struct packet_ctx *ctx)
  {
      if (ctx->ready)
      {
          /* ... */
      }
      else
      {
          /* ... */
      }
  }
  ```

- Put a space between a function name and `(` in declarations and definitions.
- Use snake_case.  Non-static functions begin with `lsquic_`.  Function names
  normally consist of a module name followed by a verb; otherwise begin with
  a verb.  Do not begin static function names with an underscore.
- Prefix a function with `maybe_` when it checks whether the requested action
  is applicable and may return without performing it.  Reserve an unqualified
  action name for a function that performs the action whenever it is called.
- Prefix structure members with an abbreviation derived from the structure
  name, matching nearby members.
- Outside the user-facing API, use `struct foo *` rather than `foo_t *` and do
  not introduce typedefs for structs, unions, or enums.  Integral typedefs are
  acceptable when consistent with existing code.
- Prefer enums to `#define` constants unless a value is larger than 2^31.  Do
  not assign explicit enum values unless the values are semantically required.
- Avoid bitfields.  Use enum bitmasks for flags and `signed char` for boolean
  structure members where appropriate.
- Use uppercase hexadecimal digits.
- Avoid ternary expressions unless the whole expression fits clearly on one
  line.
- Prefer an explicit `else` when both branches return.  This is the opposite
  of the convention commonly called `no-else-return`; the alternative without
  `else` is also described as an early-return or guard-clause style.  Write:

  ```c
  if (cond())
      return X;
  else
      return Y;
  ```

  rather than:

  ```c
  if (cond())
      return X;
  return Y;
  ```

- When several conditionals select mutually exclusive outcomes, prefer one
  visible `if`/`else if`/`else` chain over independent early returns followed
  by implicit fallthrough.  This keeps the complete branching structure easy
  to scan.  Write:

  ```c
  if (a())
  {
      some_code();
      return X;
  }
  else if (b())
      return Y;
  else
  {
      some_other_code();
      return Z;
  }
  ```

  rather than ending each independent conditional and relying on control to
  fall through to the next return.
- Early guard-clause returns are acceptable in long functions--roughly longer
  than one screenful--or when the extra indentation would split or obscure
  long lines.  Use them near the start to reject exceptional or disabled
  cases, then keep the main path unindented:

  ```c
  int
  foo (struct args *args)
  {
      if (!args->enabled)
          return -1;

      /* Lots of code here. */
      return 0;
  }
  ```

  This is a preference for structured conditional flow and fewer scattered
  early returns, not a strict single-exit rule.
- Do not add needless casts, including casts of return values.  Mark an unused
  parameter by prefixing its name with `UNUSED_`; do not cast it to `(void)`.
- Avoid including one project header from another project header; prefer
  forward declarations.  Preserve includes required by an existing public or
  platform API.
- In callback-heavy structures, put a function pointer's return type on its own
  line and align callback member names as nearby code does.  Omit obvious
  parameter names in function pointer types unless the names add clarity.
- Use the current year when adding a new copyright notice.  Do not rewrite old
  notices merely to update the year.
- Use the existing LSQUIC logging macros and module conventions rather than
  adding ad-hoc printing in library code.

## Building

Build prerequisites include CMake, Perl, zlib, a QUIC-capable BoringSSL or
OpenSSL, and initialized HPACK/QPACK submodules.  Example binaries additionally
need libevent.  A portable Debug build using BoringSSL is:

```sh
cmake -S . -B <build-dir> \
    -DCMAKE_BUILD_TYPE=Debug \
    -DLIBSSL_DIR=<boringssl-dir> \
    -DLSQUIC_TESTS=ON
cmake --build <build-dir> -j
```

Tests are only configured in Debug builds because they rely on `assert`.
AddressSanitizer is enabled by `LSQUIC_ASAN=ON` only for eligible Clang Debug
builds; configure a separate Clang build when sanitizer coverage is relevant.
Use `LSQUIC_FIU=ON` in a separate build for fault-injection work when FIU is
installed.  Compile a separate Release configuration for performance-sensitive
or optimization-dependent changes, but do not expect it to contain the unit
tests.

## Testing

Run the narrowest relevant test while iterating, then the full Debug suite
before handing off a code change:

```sh
ctest --test-dir <build-dir> -R '^<ctest-name>$' --output-on-failure
ctest --test-dir <build-dir> --output-on-failure
```

CTest names usually omit the `test_` prefix used by the executable.  Use
`ctest --test-dir <build-dir> -N` to list the exact names.  If a failure is
order-sensitive or hard to diagnose, rerun serially with the `test-serial`
build target or `ctest -j1`.

- Put focused regression tests in `tests/test_<module>.c`, using the existing
  assertion-based style and nearby fixtures or stubs.
- Register ordinary new tests in the `TESTS` list in `tests/CMakeLists.txt`;
  use explicit `ADD_TEST` entries when a binary needs multiple argument-based
  cases or platform-specific handling.
- For parsers and wire-format code, cover malformed and truncated inputs,
  minimum and maximum encodings, and protocol-version boundaries that the
  change affects.
- For settings and public APIs, test default initialization, validation, and
  the behavior exposed to both client and server modes when applicable.
- Follow existing platform guards.  Do not make a Unix-only facility an
  unconditional dependency of a portable test.

## APIs, documentation, and generated files

- Keep changes to public headers synchronized with `docs/apiref.rst`.  Update
  `docs/tutorial.rst` or the getting-started documentation when user workflow
  or API usage changes.
- Update `docs/internals.rst` when an internal invariant, data flow, or
  major structure changes.
- When documentation changes and Sphinx plus its theme are installed, build it
  with `cmake --build <build-dir> --target docs` and fix warnings introduced by
  the change.
- Do not hand-edit any `lsquic_versions_to_string.c`; CMake generates it from
  `include/lsquic.h` using `src/liblsquic/gen-verstrs.pl`.
- When adding source files or tests, update the relevant CMake source list in
  the same change.

Before finishing, review the diff for accidental generated files, run
`git diff --check`, and report exactly which builds and tests were run.
