
[Until GitLab enforces a global Regexp timeout](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/145679) you should pass an explicit timeout parameter, particularly when using advanced features or a large number of repetitions. For example:

```ruby
Regexp.new('^a*b?a*()\1$', timeout: 1) # timeout in seconds
```

#### Ruby before 3.2.0

GitLab has `Gitlab::UntrustedRegexp`
 which internally uses the [`re2`](https://github.com/google/re2/wiki/Syntax) library.
`re2` does not support backtracking so we get constant execution time, and a smaller subset of available regex features.

All user-provided regular expressions should use `Gitlab::UntrustedRegexp`.

For other regular expressions, here are a few guidelines:

- If there's a clean non-regex solution, such as `String#start_with?`, consider using it
- Ruby supports some advanced regex features like [atomic groups](https://www.regular-expressions.info/atomic.html)
  and [possessive quantifiers](https://www.regular-expressions.info/possessive.html) that eliminate backtracking
- Avoid nested quantifiers if possible (for example `(a+)+`)
- Try to be as precise as possible in your regex and avoid the `.` if there's an alternative
  - For example, Use `_[^_]+_` instead of `_.*_` to match `_text here_`
- Use reasonable ranges (for example, `{1,10}`) for repeating patterns instead of unbounded `*` and `+` matchers
- When possible, perform simple input validation such as maximum string length checks before using regular expressions
- If in doubt, don't hesitate to ping `@gitlab-com/gl-security/appsec`

## Server Side Request Forgery (SSRF)

### Description

A Server-side Request Forgery (SSRF) is an attack in which an attacker
is able to coerce an application into making an outbound request to an unintended
resource. This resource is usually internal. In GitLab, the connection most
commonly uses HTTP, but an SSRF can be performed with any protocol, such as
Redis or SSH.

With an SSRF attack, the UI may or may not show the response. The latter is
called a Blind SSRF. While the impact is reduced, it can still be useful for
attackers, especially for mapping internal network services as part of recon.

### Impact

The impact of an SSRF can vary, depending on what the application server
can communicate with, how much the attacker can control of the payload, and
if the response is returned back to the attacker. Examples of impact that
have been reported to GitLab include:

- Network mapping of internal services
