# gitlab-diff

Diff parsing, inline and word diff, and diff formatting, extracted from the GitLab
Rails monolith. The gem has no ActiveRecord: everything GitLab-specific comes in
through ports on `Gitlab::Diff::Configuration`.

Constants keep their names, such as `Gitlab::Diff::Line`, `Gitlab::WordDiff::Parser`
and `Gitlab::StringRangeMarker`, so no call site changes when a file moves here.

## What belongs here

Code that works on diff text and diff lines: parsing unified and word diffs,
marking inline changes, pairing lines for the parallel view, and the position
formatters.

Code that reads repositories, caches or the database stays in the monolith for
now, for example `Gitlab::Diff::File`, the file collections, highlighting,
`Gitlab::Diff::Position` and the position tracer. `Gitlab::Diff` is a namespace
the gem and the monolith share: the gem defines it, and the monolith's files under
`lib/gitlab/diff/` add to it.

## Configuration

The monolith wires the ports in `config/initializers/0_gitlab_diff.rb`:

```ruby
Gitlab::Diff.configure do |config|
  config.binary_notice = ->(text) { Gitlab::Git::Diff.has_binary_notice?(text) }
end
```

An input accepts a plain value or a callable. Callables are resolved on every
read, and the reader passes its arguments through. Reading an input that was
never set raises `Gitlab::Diff::MissingConfigurationError`, which names the input.

| Input | Shape | GitLab adapter |
| --- | --- | --- |
| `diff_line_code` | `(file_path, new_pos, old_pos)`, returns the legacy line code | `Gitlab::Git.diff_line_code` |
| `binary_notice` | `(text)`, read as `binary_notice?` | `Gitlab::Git::Diff.has_binary_notice?` |
| `serialize_line` | `(line)`, returns the line's JSON | `DiffLineSerializer` |

`diff_line_code` and `binary_notice` come from `Gitlab::Git`. They can become a
gem dependency instead of ports once `Gitlab::Git` is in a gem of its own.

The gem's own specs drive the inputs with in-memory fakes, set in
`spec/spec_helper.rb`. `spec/initializers/gitlab_diff_spec.rb` in the monolith
covers the adapters.

## How it is loaded

The entry point is `lib/gitlab/diff/all.rb`. It requires every file the gem owns.
The monolith loads it from `config/application.rb`, next to `require 'banzai/all'`,
before Zeitwerk initializes. `spec/fast_spec_helper.rb` does the same, and also
loads the initializer.

## Adding a file

1. Move the source file with `git mv` from `lib/gitlab/` to
   `gems/gitlab-diff/lib/gitlab/`.
2. Move its spec with `git mv` from `spec/lib/gitlab/` to
   `gems/gitlab-diff/spec/gitlab/`. A spec that needs a repository either builds
   its input from a diff string or stays behind as integration coverage.
3. Add a `require_relative` line for the new file to `lib/gitlab/diff/all.rb`.
4. Move any entries for the old paths from `.rubocop_todo/` to this gem's
   `.rubocop.yml`, and remove them from `spec/support/rspec_order_todo.yml`.

## Development

Run these from the gem directory:

```shell
bundle install
bundle exec rspec
bundle exec rubocop
```
