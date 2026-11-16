# strict-uri-parser

Splits an absolute URI into scheme, authority, path, query, and fragment
without allocating.

```rust
use strict_uri_parser::parse;

let uri = parse("https://example.org/a/b?x=1#frag").unwrap();
assert_eq!(uri.scheme, "https");
assert_eq!(uri.authority, Some("example.org"));
assert_eq!(uri.path, "/a/b");
assert_eq!(uri.query, Some("x=1"));
assert_eq!(uri.fragment, Some("frag"));
assert_eq!(uri.path_and_query(), "/a/b?x=1#frag");
```

The crate exports two items: the function `parse`, which returns
`Result<Uri<'_>, ParseError>`, and the struct `Uri<'a>`, whose fields
`scheme`, `authority`, `path`, `query`, and `fragment` are all borrowed
slices of the input. `authority`, `query`, and `fragment` are `Option<&str>`
so that an absent component is distinguishable from an empty one. `Uri`
also has a method `path_and_query()` that returns the path together with
its query and fragment, which is the form HTTP request lines use.

## Why this exists

Most URI parsers in the ecosystem return owned `String`s for each component,
which means every parse is a handful of heap allocations even when the
caller only wants to look at a hostname or compare a scheme. This crate
returns borrowed slices into the original input, so parsing a URI is a
single pass over the bytes with no allocation at all. The trade-off is
that the parser is strict: it validates the scheme grammar and rejects
raw control bytes, spaces, and non-ASCII bytes in the other components,
returning a `ParseError` instead of silently accepting malformed input.
If you need to accept whatever the network sends you, this is not the
right parser; if you are parsing URIs you produced yourself or that have
already passed through a validating front end, the zero-allocation path
is worth the strictness.

## The awkward edge

The parser follows RFC 3986's precedence for the `?` and `#` delimiters:
`#` terminates the query, so a `?` inside a fragment belongs to the
fragment. `parse("http://example.org/p#a?b")` therefore yields a fragment
of `"a?b"` and no query. The authority component is recognised only when
the text after the scheme begins with `//`; a URI such as `mailto:user@example.org`
has no authority and its whole remainder is the path. The parser checks
that every `%` is followed by two hexadecimal digits but does not decode
the escape, because decoding would require an allocation and the caller
may not want the decoded bytes.

## Errors

`ParseError` has one variant per component plus one for malformed
percent-encoding: `InvalidScheme`, `InvalidAuthority`, `InvalidPath`,
`InvalidQuery`, `InvalidFragment`, and `InvalidPercentEncoding`.
