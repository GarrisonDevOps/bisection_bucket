# gitlab-platform-core

This gem holds cross-cutting GitLab infrastructure code extracted out of
the monolith's `lib/gitlab/`. It is a deliberately coarse destination: the
one-time wiring cost (gemspec, lockfiles, CI child pipeline, RubyGems name,
initializer require) is paid once, so that code can move in afterwards
through many small, independently revertable merge requests.

## What belongs here

`gitlab-platform-core` takes broader cross-cutting infrastructure code.
The sibling gem `gitlab-utils` stays narrow: generic, stateless helper
methods such as `Gitlab::Json` and `Gitlab::Uuid`. `gitlab-platform-core`
may depend on `gitlab-utils`, but the two gems are intentionally not merged.

A file is a candidate for this gem only if all hold:

- Generic and domain-agnostic: the code would make sense outside GitLab, in
  the spirit of `gitlab-utils`. GitLab-specific Git concepts (default branch names, hashed
  repository storage paths), markup and diff helpers, and GitLab product
  concepts (label colours, tab-width user preferences) do not belong here,
  even when the class has no dependencies. Those stay in `lib/gitlab/`.
- No EE surface: no `prepend_mod` or `prepend_mod_with` call, no
  `extend_mod` or `include_mod` call, and no `ee/lib/ee/gitlab/<same path>`
  counterpart.
- No Rails or ActiveRecord coupling: no `Rails.`, `ActiveRecord`,
  `Feature.enabled?`, `Gitlab::CurrentSettings`, `Gitlab.config`,
  `Settings.`, `Gitlab::Redis`, or `Gitlab::AppLogger`. Monolith state must
  come in through an injected seam instead.

Tracking issue for the extraction:
https://gitlab.com/gitlab-org/gitlab/-/issues/616907

## Naming and paths

Constants keep their original names and paths. Moving a file into this gem
never changes a call site. For example `Gitlab::ContentTypes` stays
`Gitlab::ContentTypes` and lives at
`gems/gitlab-platform-core/lib/gitlab/content_types.rb`. There is no
re-namespacing to `Gitlab::Platform::Core::*`.

`Gitlab::Platform::Core` itself only holds the gem's own `VERSION` and the
`all.rb` require manifest. It is not a namespace for extracted constants.

## How it is loaded

The entry point is `lib/gitlab/platform/core/all.rb`. It requires every
file the gem owns. The monolith loads it from `config/application.rb`:

```ruby
require 'gitlab/platform/core/all'
```

This sits next to the existing `require 'gitlab/utils/all'`. Both requires
run before Zeitwerk initializes, so the constants are real modules by the
time autoloading starts.

## Adding a file

1. Move the source file with `git mv` from `lib/gitlab/` to
   `gems/gitlab-platform-core/lib/gitlab/`.
2. Move its spec with `git mv` from `spec/lib/gitlab/` to
   `gems/gitlab-platform-core/spec/gitlab/`.
3. Add a `require_relative` line for the new file to
   `lib/gitlab/platform/core/all.rb`.
4. Remove any stale entries for the old paths from `.rubocop_todo/` and
   from `spec/support/rspec_order_todo.yml`.

## Development

Run these from the gem directory:

```shell
bundle install
bundle exec rspec
bundle exec rubocop
```
