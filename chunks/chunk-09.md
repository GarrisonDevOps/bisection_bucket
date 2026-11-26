
```ruby
requires :file_path, type: String, file_path: true
```

Absolute paths are not allowed by default. If allowing an absolute path is required, you
need to provide an array of paths to the parameter `allowlist`.

### Misleading behavior

Some methods used to construct file paths can have non-intuitive behavior. To properly validate user input, be aware
of these behaviors.

The Ruby method [`Pathname.join`](https://ruby-doc.org/stdlib-2.7.4/libdoc/pathname/rdoc/Pathname.html#method-i-join)
joins path names. Using methods in a specific way can result in a path name typically prohibited in
typical use. In the examples below, we see attempts to access `/etc/passwd`, which is a sensitive file:

```ruby
require 'pathname'

p = Pathname.new('tmp')
print(p.join('log', 'etc/passwd', 'foo'))
# => tmp/log/etc/passwd/foo
```

Assuming the second parameter is user-supplied and not validated, submitting a new absolute path
results in a different path:

```ruby
print(p.join('log', '/etc/passwd', ''))
# renders the path to "/etc/passwd", which is not what we expect!
```

## OS command injection guidelines

Command injection is an issue in which an attacker is able to execute arbitrary commands on the host
operating system through a vulnerable application. Such attacks don't always provide feedback to a
user, but the attacker can use simple commands like `curl` to obtain an answer.

### Impact

The impact of command injection greatly depends on the user context running the commands, as well as
how data is validated and sanitized. It can vary from low impact because the user running the
injected commands has limited rights, to critical impact if running as the root user.

Potential impacts include:

- Execution of arbitrary commands on the host machine.
- Unauthorized access to sensitive data, including passwords and tokens in secrets or configuration
  files.
- Exposure of sensitive system files on the host machine, such as `/etc/passwd/` or `/etc/shadow`.
- Compromise of related systems and services gained through access to the host machine.

You should be aware of and take steps to prevent command injection when working with user-controlled
data that are used to run OS commands.

### Mitigation and prevention

To prevent OS command injections, user-supplied data shouldn't be used within OS commands. In cases
where you can't avoid this:

- Validate user-supplied data against an allowlist.
- Ensure that user-supplied data only contains alphanumeric characters (and no syntax or whitespace
  characters, for example).
- Always use `--` to separate options from arguments.

Consider using `system("command", "arg0", "arg1", ...)` whenever you can. This prevents an attacker
