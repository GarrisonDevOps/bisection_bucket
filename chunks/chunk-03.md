  - This can help an attacker gather information about internal services
    that could be used in further attacks. [More details](https://gitlab.com/gitlab-org/gitlab-foss/-/issues/51327).
- Reading internal services, including cloud service metadata.
  - The latter can be a serious problem, because an attacker can obtain keys that allow control of the victim's cloud infrastructure. (This is also a good reason
    to give only necessary privileges to the token). [More details](https://gitlab.com/gitlab-org/gitlab-foss/-/issues/51490).
- When combined with CRLF vulnerability, remote code execution. [More details](https://gitlab.com/gitlab-org/gitlab-foss/-/issues/41293).

### When to Consider

- When the application makes any outbound connection

### Mitigations

In order to mitigate SSRF vulnerabilities, it is necessary to validate the destination of the outgoing request, especially if it includes user-supplied information.

The preferred SSRF mitigations within GitLab are:

1. Only connect to known, trusted domains/IP addresses.
1. Use the [`Gitlab::HTTP`](#gitlab-http-library) library
1. Implement [feature-specific mitigations](#feature-specific-mitigations)

#### GitLab HTTP Library

The [`Gitlab::HTTP`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/http.rb) wrapper library has grown to include mitigations for all of the GitLab-known SSRF vectors. It is also configured to respect the
`Outbound requests` options that allow instance administrators to block all internal connections, or limit the networks to which connections can be made.
The `Gitlab::HTTP` wrapper library delegates the requests to the [`gitlab-http`](https://gitlab.com/gitlab-org/gitlab/-/tree/master/gems/gitlab-http) gem.

In some cases, it has been possible to configure `Gitlab::HTTP` as the HTTP
connection library for 3rd-party gems. This is preferable over re-implementing
the mitigations for a new feature.

- [More details](https://dev.gitlab.org/gitlab/gitlabhq/-/merge_requests/2530/diffs)

#### URL blocker & validation libraries

[`Gitlab::HTTP_V2::UrlBlocker`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/gems/gitlab-http/lib/gitlab/http_v2/url_blocker.rb) can be used to validate that a
provided URL meets a set of constraints. Importantly, when `dns_rebind_protection` is `true`, the method returns a known-safe URI where the hostname
has been replaced with an IP address. This prevents DNS rebinding attacks, because the DNS record has been resolved. However, if we ignore this returned
value, we will not be protected against DNS rebinding.

This is the case with validators such as the `AddressableUrlValidator` (called with `validates :url, addressable_url: {opts}` or `public_url: {opts}`).
