
```ruby
# Vulnerable tar.gz extraction example!

begin
  tar_extract = Gem::Package::TarReader.new(Zlib::GzipReader.open("/tmp/uploaded.tar.gz"))
rescue Errno::ENOENT
  STDERR.puts("archive file does not exist or is not readable")
  exit(false)
end
tar_extract.rewind

# Loop over each entry and output file contents
tar_extract.each do |entry|
  next if entry.directory?

  # Oops! We don't check if the file is actually a symbolic link to a potentially sensitive file.
  puts entry.read
end
```

#### Best practices

Always check the type of the archive entry before reading the contents and ignore entries that are not plain files. If you absolutely must support symbolic links, ensure that they only point to files inside the archive and nowhere else.

```ruby
# tar.gz extraction example with protection against symlink attacks.

begin
  tar_extract = Gem::Package::TarReader.new(Zlib::GzipReader.open("/tmp/uploaded.tar.gz"))
rescue Errno::ENOENT
  STDERR.puts("archive file does not exist or is not readable")
  exit(false)
end
tar_extract.rewind

# Loop over each entry and output file contents
tar_extract.each do |entry|
  next if entry.directory?

  # By skipping symbolic links entirely, we are sure they can't cause any trouble!
  next if entry.symlink?

  puts entry.read
end
```

## URL Spoofing

We want to protect our users from bad actors who might try to use GitLab
features to redirect other users to malicious sites.

Many features in GitLab allow users to post links to external websites. It is
important that the destination of any user-specified link is made very clear
to the user.

### `external_redirect_path`

When presenting links provided by users, if the actual URL is hidden, use the `external_redirect_path`
helper method to redirect the user to a warning page first. For example:

```ruby
# Bad :(
# This URL comes from User-Land and may not be safe...
# We need the user to see where they are going.
link_to foo_social_url(@user), title: "Foo Social" do
  sprite_icon('question-o')
end

# Good :)
# The external_redirect "leaving GitLab" page will show the URL to the user
# before they leave.
link_to external_redirect_path(url: foo_social_url(@user)), title: "Foo" do
  sprite_icon('question-o')
end
```

Also see this [real-life usage](https://gitlab.com/gitlab-org/gitlab/-/blob/bdba5446903ff634fb12ba695b2de99b6d6881b5/app/helpers/application_helper.rb#L378) as an example.

## Email and notifications

Ensure that only intended recipients get emails and notifications. Even if your
