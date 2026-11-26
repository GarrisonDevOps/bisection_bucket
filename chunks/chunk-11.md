rescue Errno::ENOENT
  STDERR.puts("archive file does not exist or is not readable")
  exit(false)
end
tar_extract.rewind

tar_extract.each do |entry|
  next unless entry.file? # Only process files in this example for simplicity.

  destination = "/tmp/extracted/#{entry.full_name}" # Oops! We blindly use the entry filename for the destination.
  File.open(destination, "wb") do |out|
    out.write(entry.read)
  end
end
```

#### Best practices

Always expand the destination file path by resolving all potential directory traversals and other sequences that can alter the path and refuse extraction if the final destination path does not start with the intended destination directory.

```ruby
# tar.gz extraction example with protection against Zip Slip attacks.

begin
  tar_extract = Gem::Package::TarReader.new(Zlib::GzipReader.open("/tmp/uploaded.tar.gz"))
rescue Errno::ENOENT
  STDERR.puts("archive file does not exist or is not readable")
  exit(false)
end
tar_extract.rewind

tar_extract.each do |entry|
  next unless entry.file? # Only process files in this example for simplicity.

  # safe_destination will raise an exception in case of Zip Slip / directory traversal.
  destination = safe_destination(entry.full_name, "/tmp/extracted")

  File.open(destination, "wb") do |out|
    out.write(entry.read)
  end
end

def safe_destination(filename, destination_dir)
  raise "filename cannot start with '/'" if filename.start_with?("/")

  destination_dir = File.realpath(destination_dir)
  destination = File.expand_path(filename, destination_dir)

  raise "filename is outside of destination directory" unless
    destination.start_with?(destination_dir + "/"))

  destination
end
```

```ruby
# zip extraction example using rubyzip with built-in protection against Zip Slip attacks.
require 'zip'

Zip::File.open("/tmp/uploaded.zip") do |zip_file|
  zip_file.each do |entry|
    # Extract entry to /tmp/extracted directory.
    entry.extract("/tmp/extracted")
  end
end
```

### Symlink attacks

Symlink attacks make it possible for an attacker to read the contents of arbitrary files on the server of a vulnerable application. While it is a high-severity vulnerability that can often lead to remote code execution and other critical vulnerabilities, it is only exploitable in scenarios where a vulnerable application accepts archive files from the attacker and somehow displays the extracted contents back to the attacker without any validation or sanitization of symbolic links inside the archive.

### Insecure archive symlink extraction examples

For zip files, the [`rubyzip`](https://rubygems.org/gems/rubyzip) Ruby gem is already patched against symlink attacks as it ignores symbolic links, so for this vulnerable example we will extract a `tar.gz` file with `Gem::Package::TarReader`:
