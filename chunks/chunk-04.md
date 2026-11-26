Validation errors are only raised when validations are called, for example when a record is created or saved. If we ignore the value returned by the validation
when persisting the record, we need to recheck its validity before using it. For more information, see [Time of check to time of use bugs](_index.md#time-of-check-to-time-of-use-bugs).

#### Feature-specific mitigations

There are many tricks to bypass common SSRF validations. If feature-specific mitigations are necessary, they should be reviewed by the AppSec team, or a developer who has worked on SSRF mitigations previously.

For situations in which you can't use an allowlist or `GitLab:HTTP`, you must implement mitigations
directly in the feature. It's best to validate the destination IP addresses themselves, not just
domain names, as the attacker can control DNS. Below is a list of mitigations that you should
implement.

- Block connections to all localhost addresses
  - `127.0.0.1/8` (IPv4 - note the subnet mask)
  - `::1` (IPv6)
- Block connections to networks with private addressing (RFC 1918)
  - `10.0.0.0/8`
  - `172.16.0.0/12`
  - `192.168.0.0/24`
- Block connections to link-local addresses (RFC 3927)
  - `169.254.0.0/16`
  - In particular, for GCP: `metadata.google.internal` -> `169.254.169.254`
- For HTTP connections: Disable redirects or validate the redirect destination
- To mitigate DNS rebinding attacks, validate and use the first IP address received.

See [`url_blocker_spec.rb`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/spec/lib/gitlab/url_blocker_spec.rb) for examples of SSRF payloads. For more information about the DNS-rebinding class of bugs, see [Time of check to time of use bugs](_index.md#time-of-check-to-time-of-use-bugs).

Don't rely on methods like `.start_with?` when validating a URL, or make assumptions about which
part of a string maps to which part of a URL. Use the `URI` class to parse the string, and validate
each component (scheme, host, port, path, and so on). Attackers can create valid URLs which look
safe, but lead to malicious locations.

```ruby
user_supplied_url = "https://my-safe-site.com@my-evil-site.com" # Content before an @ in a URL is usually for basic authentication
user_supplied_url.start_with?("https://my-safe-site.com")       # Don't trust with start_with? for URLs!
=> true
URI.parse(user_supplied_url).host
=> "my-evil-site.com"

user_supplied_url = "https://my-safe-site.com-my-evil-site.com"
user_supplied_url.start_with?("https://my-safe-site.com")      # Don't trust with start_with? for URLs!
=> true
URI.parse(user_supplied_url).host
