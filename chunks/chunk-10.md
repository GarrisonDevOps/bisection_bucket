from concatenating commands.

For more examples on how to use shell commands securely, consult
[Guidelines for shell commands in the GitLab codebase](../shell_commands.md).
It contains various examples on how to securely call OS commands.

## Working with archive files

Working with archive files like `zip`, `tar`, `jar`, `war`, `cpio`, `apk`, `rar`, and `7z` presents an area where potentially critical security vulnerabilities can sneak into an application.

### Utilities for safely working with archive files

There are common utilities that can be used to securely work with archive files.

| Archive type | Utility     |
|--------------|-------------|
| `zip`        | `SafeZip`   |

#### `SafeZip`

SafeZip provides a safe interface to extract specific directories or files within a `zip` archive through the `SafeZip::Extract` class.

Example:

```ruby
Dir.mktmpdir do |tmp_dir|
  SafeZip::Extract.new(zip_file_path).extract(files: ['index.html', 'app/index.js'], to: tmp_dir)
  SafeZip::Extract.new(zip_file_path).extract(directories: ['src/', 'test/'], to: tmp_dir)
rescue SafeZip::Extract::EntrySizeError
  raise Error, "Path `#{file_path}` has invalid size in the zip!"
end
```

### Zip Slip

In 2018, the security company Snyk [released a blog post](https://security.snyk.io/research/zip-slip-vulnerability) describing research into a widespread and critical vulnerability present in many libraries and applications which allows an attacker to overwrite arbitrary files on the server file system which, in many cases, can be leveraged to achieve remote code execution. The vulnerability was dubbed Zip Slip.

A Zip Slip vulnerability happens when an application extracts an archive without validating and sanitizing the filenames inside the archive for directory traversal sequences that change the file location when the file is extracted.

Example malicious filenames:

- `../../etc/passwd`
- `../../root/.ssh/authorized_keys`
- `../../etc/gitlab/gitlab.rb`

If a vulnerable application extracts an archive file with any of these filenames, the attacker can overwrite these files with arbitrary content.

### Insecure archive extraction examples

For zip files, the [`rubyzip`](https://rubygems.org/gems/rubyzip) Ruby gem is already patched against the Zip Slip vulnerability and will refuse to extract files that try to perform directory traversal, so for this vulnerable example we will extract a `tar.gz` file with `Gem::Package::TarReader`:

```ruby
# Vulnerable tar.gz extraction example!

begin
  tar_extract = Gem::Package::TarReader.new(Zlib::GzipReader.open("/tmp/uploaded.tar.gz"))
