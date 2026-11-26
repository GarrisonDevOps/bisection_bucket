
Path Traversal vulnerabilities grant attackers access to arbitrary directories and files on the server that is executing an application. This can include data, code, or credentials.

Traversal can occur when a path includes directories. A typical malicious example includes one or more `../`, which tells the file system to look in the parent directory. Supplying many of them in a path, for example `../../../../../../../etc/passwd`, usually resolves to `/etc/passwd`. If the file system is instructed to look back to the root directory and can't go back any further, then extra `../` are ignored. The file system then looks from the root, resulting in `/etc/passwd` - a file you definitely do not want exposed to a malicious attacker!

### Impact

Path Traversal attacks can lead to multiple critical and high severity issues, like arbitrary file read, remote code execution, or information disclosure.

### When to consider

When working with user-controlled filenames/paths and file system APIs.

### Mitigation and prevention

In order to prevent Path Traversal vulnerabilities, user-controlled filenames or paths should be validated before being processed.

- Comparing user input against an allowlist of allowed values or verifying that it only contains allowed characters.
- After validating the user supplied input, it should be appended to the base directory and the path should be canonicalized using the file system API.

#### GitLab specific validations

The methods `Gitlab::PathTraversal.check_path_traversal!()` and `Gitlab::PathTraversal.check_allowed_absolute_path!()`
can be used to validate user-supplied paths and prevent vulnerabilities.
`check_path_traversal!()` will detect their Path Traversal payloads and accepts URL-encoded paths.
`check_allowed_absolute_path!()` will check if a path is absolute and whether it is inside the allowed path list. By default, absolute
paths are not allowed, so you need to pass a list of allowed absolute paths to the `path_allowlist`
parameter when using `check_allowed_absolute_path!()`.

To use a combination of both checks, follow the example below:

```ruby
Gitlab::PathTraversal.check_allowed_absolute_path_and_path_traversal!(path, path_allowlist)
```

In the REST API, we have the [`FilePath`](https://gitlab.com/gitlab-org/security/gitlab/-/blob/master/lib/api/validations/validators/file_path.rb)
validator that can be used to perform the checking on any file path argument the endpoints have.
It can be used as follows:

```ruby
requires :file_path, type: String, file_path: { allowlist: ['/foo/bar/', '/home/foo/', '/app/home'] }
```

The Path Traversal check can also be used to forbid any absolute path:
