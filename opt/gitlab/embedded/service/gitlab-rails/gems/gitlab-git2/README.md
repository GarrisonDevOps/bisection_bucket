# gitlab-git2

`Gitlab::Git` and `Gitlab::GitalyClient`, to be extracted from the GitLab Rails
monolith.

RubyGems refuses `gitlab-git` as too similar to `gitlab_git`, an older gem
for `Gitlab::Git`, so this gem is named `gitlab-git2`.

For now the gem holds only its test harness. It proves that the gem's specs can
run against a real Gitaly server, so that the specs for `Gitlab::Git` and
`Gitlab::GitalyClient` can move with the code instead of staying in the
monolith.

## Gitaly for the specs

`spec/support/gitaly_server.rb` starts a private Gitaly before the suite, from
the binaries in `GITALY_BIN_DIR`. It defaults to the monolith's
`tmp/tests/gitaly/_build/bin`, which `scripts/gitaly-test-build` builds. The
server gets its own socket, storage and token, so it doesn't interfere with a
Gitaly that the monolith's specs use.

`spec/support/fixture_repository.rb` creates repositories in that server from a
bundle of the monolith's `spec/support/gitlab-git-test.git`, through Gitaly's
`CreateRepositoryFromBundle`. That is the same RPC `create(:project,
:repository)` uses.

Examples tagged `:gitaly` are skipped locally when there are no binaries. In CI
a missing Gitaly fails the suite.

In CI, the gem's `rspec` job needs the parent pipeline's `setup-test-env` job,
and starts Gitaly from its artifacts. The `gems:test` trigger job in
`.gitlab/ci/gems.gitlab-ci.yml` waits for `setup-test-env`.

## Development

Build Gitaly once from the monolith root, then run these from the gem
directory:

```shell
bundle install
bundle exec rspec
bundle exec rubocop
```
