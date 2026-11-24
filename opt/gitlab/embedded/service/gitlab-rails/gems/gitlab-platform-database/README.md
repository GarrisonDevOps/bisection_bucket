# gitlab-platform-database

The database area of the `gitlab-platform` gem family. It holds code extracted
out of the monolith's `lib/gitlab/database/`, and it is a sibling of
`gitlab-platform-core`, which holds the cross-cutting infrastructure.

## What belongs here

A file is a candidate for this gem only if all of these hold:

- It depends on nothing outside `activerecord`, `pg` and `gitlab-utils`. An
  area gem may depend on `gitlab-platform-core`, but never on another area gem.
- No EE surface: no `prepend_mod`, `extend_mod` or `include_mod` call, and no
  `ee/lib/ee/gitlab/database/<same path>` counterpart.
- No monolith coupling: no `app/models` or `ee/app/models` constant, no
  `Feature.enabled?`, no `Gitlab.com?` or `Gitlab.dev_or_test_env?`, and nothing
  that reads `Rails` or `Gitlab` configuration at load time. Monolith state has
  to come in through an injected seam instead.
- Its spec holds to the same bar. A spec that needs `ApplicationRecord` or a
  live database connection keeps the file in the monolith, even when the source
  file itself would qualify.

## Naming and paths

Constants keep their original names and paths, so moving a file into this gem
never changes a call site. `Gitlab::Database::Type::JsonPgSafe` stays
`Gitlab::Database::Type::JsonPgSafe` and lives at
`gems/gitlab-platform-database/lib/gitlab/database/type/json_pg_safe.rb`.

`Gitlab::Platform::Database` holds only the gem's own `VERSION` and the `all.rb`
require manifest. It is not a namespace for extracted constants.

## How it is loaded

The entry point is `lib/gitlab/platform/database/all.rb`, which requires every
file the gem owns. The monolith loads it from `config/application.rb`:

```ruby
require 'gitlab/platform/database/all'
```

That sits next to the existing `require 'gitlab/utils/all'`, and runs before
Zeitwerk initializes, so the constants are real classes before any `app/models`
class body calls `::Gitlab::Database::Type::IndifferentJsonb.new`.

### Sharing the `Gitlab::Database` namespace with the monolith

The monolith keeps `Gitlab::Database` itself in `lib/gitlab/database.rb`, and
this gem reopens that module. Zeitwerk skips a file whose constant is already
defined, so without help `lib/gitlab/database.rb` would never be loaded.

Nothing extra is needed here, because the monolith already carries the fix in
`config/initializers/0_load_gitlab_database.rb`. That initializer predates this
gem — `gitlab-database-data_isolation` opens the same namespace during
`Bundler.require` — and it requires `lib/gitlab/database.rb` explicitly, so the
methods defined there are present for every later initializer.

This gem is deliberately not required from `spec/fast_spec_helper.rb`. Requiring
it before `spec/rails_autoload.rb` would shadow `lib/gitlab/database.rb` in fast
specs with no initializer to compensate, and requiring it afterwards would
resolve the pending Zeitwerk autoload and pull the whole of that file into every
fast spec. No fast spec needs either.

## Adding a file

1. `git mv` the source from `lib/gitlab/database/` to
   `gems/gitlab-platform-database/lib/gitlab/database/`.
2. `git mv` its spec from `spec/lib/gitlab/database/` to
   `gems/gitlab-platform-database/spec/gitlab/database/`.
3. Add a `require_relative` line to `lib/gitlab/platform/database/all.rb`.
4. Remove the old paths from `.rubocop_todo/` and from
   `spec/support/rspec_order_todo.yml`.

## Development

Run these from the gem directory:

```shell
bundle install
bundle exec rspec
bundle exec rubocop
```
