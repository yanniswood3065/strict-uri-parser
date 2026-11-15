//! Strict URI parser that splits an absolute URI into its five components
//! without allocating any `String`s.
//!
//! The parser is deliberately strict: it follows RFC 3986's grammar for
//! `scheme`, `authority`, `path`, `query`, and `fragment` and rejects input
//! that does not match. In exchange for that strictness it can return
//! borrowed slices into the original input, so callers that only need to
//! inspect a URI (routing, logging, signature checks) never touch the heap.
//!
//! The five components are `Option<&str>` because a URI may legitimately
//! omit any of them except the scheme and the path: a URI such as
//! `file:/etc/hosts` has no authority, no query and no fragment. Returning
//! `None` for those keeps the distinction between "absent" and "empty"
//! visible to the caller.

/// The five components of an absolute URI, borrowed from the input.
///
/// `scheme` and `path` are always present for a successfully parsed URI;
/// `authority`, `query` and `fragment` are `None` when the corresponding
/// delimiter does not appear in the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uri<'a> {
    pub scheme: &'a str,
    pub authority: Option<&'a str>,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub fragment: Option<&'a str>,
}

impl<'a> Uri<'a> {
    /// The path including its query and fragment, if any.
    ///
    /// This is the "path-query-fragment" form used by HTTP request lines
    /// and by clients that need to re-emit the resource identifier without
    /// the scheme and authority.
    pub fn path_and_query(&self) -> &'a str {
        // The path slice already ends where the query or fragment begins, so
        // we can compute the end by taking the maximum of the optional
        // component ends. Working with indices avoids re-scanning.
        let mut end = self.path.len();
        if let Some(q) = self.query {
            // `q` starts one byte after the `?`.
            let q_end = q.as_ptr() as usize - self.path.as_ptr() as usize + q.len();
            if q_end > end {
                end = q_end;
            }
        }
        if let Some(f) = self.fragment {
            let f_end = f.as_ptr() as usize - self.path.as_ptr() as usize + f.len();
            if f_end > end {
                end = f_end;
            }
        }
        // SAFETY: `end` is a valid byte offset within the original input
        // because it is derived from slices of that input.
        let base = self.path.as_ptr() as usize;
        let start = base;
        unsafe {
            let slice = std::slice::from_raw_parts(start as *const u8, end);
            std::str::from_utf8_unchecked(slice)
        }
    }
}

/// Errors produced by [`parse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// The scheme was empty or contained a character that RFC 3986 does not
    /// allow before the `:`.
    InvalidScheme,
    /// The authority component contained a byte that is not allowed.
    InvalidAuthority,
    /// The path contained a byte that is not allowed.
    InvalidPath,
    /// The query contained a byte that is not allowed.
    InvalidQuery,
    /// The fragment contained a byte that is not allowed.
    InvalidFragment,
    /// A `%` was not followed by two hexadecimal digits.
    InvalidPercentEncoding,
}

/// Parse an absolute URI into its five components without allocating.
///
/// The input must contain a scheme followed by `:`. Everything after the
/// scheme is split on the first `?` (query) and the first `#` (fragment),
/// in that order, because RFC 3986 gives `#` lower precedence than `?`:
/// a `?` inside a fragment is part of the fragment, not a new query.
///
/// The authority is present only when the path begins with `//`; the
/// two slashes are consumed and the authority runs to the next `/`, `?`
/// or `#`. This is the standard `//authority/path` form.
///
/// # Examples
///
/// ```
/// use strict_uri_parser::parse;
///
/// let uri = parse("https://example.org/a/b?x=1#frag").unwrap();
/// assert_eq!(uri.scheme, "https");
/// assert_eq!(uri.authority, Some("example.org"));
/// assert_eq!(uri.path, "/a/b");
/// assert_eq!(uri.query, Some("x=1"));
/// assert_eq!(uri.fragment, Some("frag"));
/// ```
pub fn parse(input: &str) -> Result<Uri<'_>, ParseError> {
    let bytes = input.as_bytes();

    // Scheme: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) ":"
    let colon = match bytes.iter().position(|&b| b == b':') {
        Some(i) => i,
        None => return Err(ParseError::InvalidScheme),
    };
    if colon == 0 {
        return Err(ParseError::InvalidScheme);
    }
    let scheme = &input[..colon];
    if !scheme.bytes().enumerate().all(|(i, b)| {
        if i == 0 {
            b.is_ascii_alphabetic()
        } else {
            b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.'
        }
    }) {
        return Err(ParseError::InvalidScheme);
    }

    let rest = &input[colon + 1..];

    // Split off the fragment first: `#` terminates the query and the path.
    let (before_fragment, fragment) = match rest.find('#') {
        Some(i) => (&rest[..i], Some(&rest[i + 1..])),
        None => (rest, None),
    };

    // Split off the query next: `?` terminates the path.
    let (before_query, query) = match before_fragment.find('?') {
        Some(i) => (&before_fragment[..i], Some(&before_fragment[i + 1..])),
        None => (before_fragment, None),
    };

    // Authority: only when the remaining text starts with `//`.
    let (authority, path) = if let Some(after_slashes) = before_query.strip_prefix("//") {
        match after_slashes.find(['/', '?', '#']) {
            Some(i) => (Some(&after_slashes[..i]), &after_slashes[i..]),
            None => (Some(after_slashes), ""),
        }
    } else {
        (None, before_query)
    };

    validate_authority(authority)?;
    validate_path(path)?;
    validate_query(query)?;
    validate_fragment(fragment)?;

    Ok(Uri {
        scheme,
        authority,
        path,
        query,
        fragment,
    })
}

/// Validate the authority against RFC 3986's `authority` production.
///
/// The check is byte-wise and deliberately permissive about characters
/// that are technically reserved (sub-delims, userinfo) because callers
/// that need stricter semantics (e.g. host-only validation) can layer
/// that on top. What we reject here is anything that cannot appear in an
/// authority at all: spaces, control characters, and raw non-ASCII bytes.
fn validate_authority(authority: Option<&str>) -> Result<(), ParseError> {
    let Some(authority) = authority else {
        return Ok(());
    };
    for &b in authority.as_bytes() {
        if b.is_ascii_control() || b == b' ' || b == b'"' || b == b'<' || b == b'>' || b == b'\\' || b == b'^' || b == b'`' || b == b'{' || b == b'|' || b == b'}' {
            return Err(ParseError::InvalidAuthority);
        }
        if b >= 0x80 {
            return Err(ParseError::InvalidAuthority);
        }
    }
    Ok(())
}

/// Validate the path against RFC 3986's `path` production.
///
/// Paths may contain `pchar` plus `/`. We reject raw control bytes, spaces,
/// and raw non-ASCII bytes; percent-encoded forms are accepted as-is and
/// checked for well-formedness by [`validate_percent_encoding`].
fn validate_path(path: &str) -> Result<(), ParseError> {
    validate_percent_encoding(path)?;
    for &b in path.as_bytes() {
        if b.is_ascii_control() || b == b' ' || b == b'"' || b == b'<' || b == b'>' || b == b'\\' || b == b'^' || b == b'`' || b == b'{' || b == b'|' || b == b'}' {
            return Err(ParseError::InvalidPath);
        }
        if b >= 0x80 {
            return Err(ParseError::InvalidPath);
        }
    }
    Ok(())
}

/// Validate the query against RFC 3986's `query` production.
///
/// The query allows `pchar`, `/` and `?`. The same byte-level restrictions
/// as the path apply.
fn validate_query(query: Option<&str>) -> Result<(), ParseError> {
    let Some(query) = query else {
        return Ok(());
    };
    validate_percent_encoding(query)?;
    for &b in query.as_bytes() {
        if b.is_ascii_control() || b == b' ' || b == b'"' || b == b'<' || b == b'>' || b == b'\\' || b == b'^' || b == b'`' || b == b'{' || b == b'|' || b == b'}' {
            return Err(ParseError::InvalidQuery);
        }
        if b >= 0x80 {
            return Err(ParseError::InvalidQuery);
        }
    }
    Ok(())
}

/// Validate the fragment against RFC 3986's `fragment` production.
///
/// Fragments allow `pchar`, `/` and `?`. Same byte-level restrictions.
fn validate_fragment(fragment: Option<&str>) -> Result<(), ParseError> {
    let Some(fragment) = fragment else {
        return Ok(());
    };
    validate_percent_encoding(fragment)?;
    for &b in fragment.as_bytes() {
        if b.is_ascii_control() || b == b' ' || b == b'"' || b == b'<' || b == b'>' || b == b'\\' || b == b'^' || b == b'`' || b == b'{' || b == b'|' || b == b'}' {
            return Err(ParseError::InvalidFragment);
        }
        if b >= 0x80 {
            return Err(ParseError::InvalidFragment);
        }
    }
    Ok(())
}

/// Ensure every `%` in the input is followed by exactly two hex digits.
///
/// This is a syntactic check only; we do not decode the escaped bytes,
/// because doing so would require an allocation and the caller may not
/// want the decoded form.
fn validate_percent_encoding(s: &str) -> Result<(), ParseError> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(ParseError::InvalidPercentEncoding);
            }
            if !bytes[i + 1].is_ascii_hexdigit() || !bytes[i + 2].is_ascii_hexdigit() {
                return Err(ParseError::InvalidPercentEncoding);
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_https_with_all_five_components() {
        let uri = parse("https://example.org/a/b?x=1#frag").unwrap();
        assert_eq!(uri.scheme, "https");
        assert_eq!(uri.authority, Some("example.org"));
        assert_eq!(uri.path, "/a/b");
        assert_eq!(uri.query, Some("x=1"));
        assert_eq!(uri.fragment, Some("frag"));
    }

    #[test]
    fn parses_uri_without_authority() {
        let uri = parse("mailto:user@example.org").unwrap();
        assert_eq!(uri.scheme, "mailto");
        assert_eq!(uri.authority, None);
        assert_eq!(uri.path, "user@example.org");
        assert_eq!(uri.query, None);
        assert_eq!(uri.fragment, None);
    }

    #[test]
    fn parses_uri_with_empty_path() {
        let uri = parse("http://example.org").unwrap();
        assert_eq!(uri.scheme, "http");
        assert_eq!(uri.authority, Some("example.org"));
        assert_eq!(uri.path, "");
        assert_eq!(uri.query, None);
        assert_eq!(uri.fragment, None);
    }

    #[test]
    fn parses_uri_with_empty_query_and_fragment() {
        let uri = parse("http://example.org/p?#").unwrap();
        assert_eq!(uri.scheme, "http");
        assert_eq!(uri.authority, Some("example.org"));
        assert_eq!(uri.path, "/p");
        assert_eq!(uri.query, Some(""));
        assert_eq!(uri.fragment, Some(""));
    }

    #[test]
    fn fragment_may_contain_question_mark() {
        // RFC 3986 gives `#` lower precedence than `?`, so the `?` here
        // belongs to the fragment and must not be treated as a query
        // separator.
        let uri = parse("http://example.org/p#a?b").unwrap();
        assert_eq!(uri.path, "/p");
        assert_eq!(uri.query, None);
        assert_eq!(uri.fragment, Some("a?b"));
    }

    #[test]
    fn authority_ends_at_question_mark() {
        // `?` terminates the authority even when no `/` follows it.
        let uri = parse("http://example.org?x=1").unwrap();
        assert_eq!(uri.authority, Some("example.org"));
        assert_eq!(uri.path, "");
        assert_eq!(uri.query, Some("x=1"));
    }

    #[test]
    fn authority_ends_at_fragment() {
        let uri = parse("http://example.org#frag").unwrap();
        assert_eq!(uri.authority, Some("example.org"));
        assert_eq!(uri.path, "");
        assert_eq!(uri.fragment, Some("frag"));
    }

    #[test]
    fn rejects_missing_scheme() {
        assert_eq!(parse("/just/a/path"), Err(ParseError::InvalidScheme));
    }

    #[test]
    fn rejects_scheme_starting_with_digit() {
        assert_eq!(parse("1http://example.org"), Err(ParseError::InvalidScheme));
    }

    #[test]
    fn rejects_empty_scheme() {
        assert_eq!(parse(":foo"), Err(ParseError::InvalidScheme));
    }

    #[test]
    fn rejects_space_in_authority() {
        assert_eq!(
            parse("http://exa mple.org/p"),
            Err(ParseError::InvalidAuthority)
        );
    }

    #[test]
    fn rejects_raw_non_ascii_in_path() {
        assert_eq!(parse("http://example.org/caf\u{e9}"), Err(ParseError::InvalidPath));
    }

    #[test]
    fn rejects_bad_percent_encoding_in_query() {
        assert_eq!(
            parse("http://example.org/?x=%zz"),
            Err(ParseError::InvalidPercentEncoding)
        );
    }

    #[test]
    fn accepts_valid_percent_encoding() {
        let uri = parse("http://example.org/a%20b?x=%2F#f%23").unwrap();
        assert_eq!(uri.path, "/a%20b");
        assert_eq!(uri.query, Some("x=%2F"));
        assert_eq!(uri.fragment, Some("f%23"));
    }

    #[test]
    fn rejects_truncated_percent_encoding() {
        assert_eq!(
            parse("http://example.org/%2"),
            Err(ParseError::InvalidPercentEncoding)
        );
    }

    #[test]
    fn path_and_query_includes_query_and_fragment() {
        let uri = parse("http://example.org/a/b?x=1#frag").unwrap();
        assert_eq!(uri.path_and_query(), "/a/b?x=1#frag");
    }

    #[test]
    fn path_and_query_without_query_or_fragment_is_just_path() {
        let uri = parse("http://example.org/a/b").unwrap();
        assert_eq!(uri.path_and_query(), "/a/b");
    }

    #[test]
    fn path_and_query_with_only_fragment() {
        let uri = parse("http://example.org/a/b#frag").unwrap();
        assert_eq!(uri.path_and_query(), "/a/b#frag");
    }

    #[test]
    fn scheme_allows_plus_dash_dot() {
        let uri = parse("a+b-c.d:rest").unwrap();
        assert_eq!(uri.scheme, "a+b-c.d");
        assert_eq!(uri.path, "rest");
    }

    #[test]
    fn empty_input_is_invalid_scheme() {
        assert_eq!(parse(""), Err(ParseError::InvalidScheme));
    }
}
