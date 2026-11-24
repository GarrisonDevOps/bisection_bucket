#!/usr/bin/env bash
# Replays ClickHouse migrations from the latest required stop, in the two
# phases Omnibus and Helm use, against seeded tables. See #593129.
set -euo pipefail
source scripts/utils.sh

: "${CLICKHOUSE_URL:=http://clickhouse:8123}"
GIT_REMOTE="${CI_REPOSITORY_URL:-origin}"
ch() { curl -sS --fail-with-body "${CLICKHOUSE_URL}/?database=${CLICKHOUSE_DATABASE}" --data-binary "$1"; }
restore_head_schema() {
  rm -rf db/click_house/schema_migrations
  git checkout HEAD -- db/click_house/main.sql db/click_house/schema_migrations/
}

# 1. Start from the latest required stop's schema.
section_start "load_stop_schema" "Loading the latest upgrade stop schema"
STOP=$(bundle exec ruby -ryaml -ractive_support/core_ext/object/blank \
  -rgitlab/utils/upgrade_path -rgitlab/version_info -e '
  stop = Gitlab::Utils::UpgradePath.new(YAML.safe_load_file("config/upgrade_path.yml"),
    Gitlab::VersionInfo.parse(File.read("VERSION").strip)).last_required_stop
  puts "#{stop.major}.#{stop.minor}"')
STOP_TAG=$(git ls-remote --tags --sort=-version:refname "${GIT_REMOTE}" "v${STOP}.*-ee" |
  grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+-ee$' | sed -n 1p)
[ -n "${STOP_TAG}" ] || { echo "No release tag found for ${STOP}" >&2; exit 1; }
echo "Upgrading from ${STOP_TAG}"

trap restore_head_schema EXIT
# Shallow only on CI: --depth on a full local clone marks it shallow.
git fetch --quiet --no-tags ${CI:+--depth 1} "${GIT_REMOTE}" "refs/tags/${STOP_TAG}:refs/tags/${STOP_TAG}"
rm -rf db/click_house/schema_migrations
git checkout "${STOP_TAG}" -- db/click_house/main.sql db/click_house/schema_migrations/
bundle exec rake gitlab:clickhouse:schema:load
restore_head_schema
section_end "load_stop_schema"

# 2. Put rows in every table, so partition-moving steps have data to compare.
section_start "seed" "Seeding every MergeTree table"
# AggregatingMergeTree tables are left to their materialized views, which fill them from the
# seeded source tables the way production does.
for table in $(ch "SELECT name FROM system.tables WHERE database = currentDatabase()
    AND engine LIKE '%MergeTree' AND engine NOT LIKE '%AggregatingMergeTree'
    AND name != 'schema_migrations'"); do
  # A random UInt8 breaks a ReplacingMergeTree is_deleted column, so those columns take their defaults.
  writable="database = currentDatabase() AND table = '${table}' AND default_kind NOT IN ('MATERIALIZED', 'ALIAS')
    AND type NOT IN ('UInt8', 'Bool')"
  columns=$(ch "SELECT arrayStringConcat(groupArray(concat('\`', name, '\`')), ', ') FROM system.columns WHERE ${writable}")
  # Batched data migrations walk id ranges in fixed steps, so keep integers small like real ids.
  bounded=$(ch "SELECT arrayStringConcat(groupArray(concat('abs(\`', name, '\`) % 1000 + 1 AS \`', name, '\`')), ', ')
    FROM system.columns WHERE ${writable} AND match(type, '^(Nullable\\\\()?U?Int')")
  error=$(ch "INSERT INTO \`${table}\` (${columns}) SELECT * ${bounded:+REPLACE (${bounded})} FROM generateRandom(1, 16, 2) LIMIT 10") ||
    echo "WARNING: could not seed ${table}: ${error}" >&2
done
# schema:load already filled schema_migrations, so counting it would let this check pass with nothing seeded.
SEEDED=$(ch "SELECT sum(rows) FROM system.parts WHERE database = currentDatabase() AND active
  AND table != 'schema_migrations'")
[ "${SEEDED}" -gt 0 ] || { echo "No rows seeded" >&2; exit 1; }
echo "Seeded ${SEEDED} rows"
section_end "seed"

# 3. Run regular migrations, then post-deployment migrations, as upgrades do.
section_start "migrate_regular" "Phase 1: regular migrations"
SKIP_POST_DEPLOYMENT_MIGRATIONS=true bundle exec rake gitlab:clickhouse:migrate
section_end "migrate_regular"

section_start "migrate_post_deploy" "Phase 2: post-deployment migrations"
bundle exec rake gitlab:clickhouse:migrate
section_end "migrate_post_deploy"

ruby scripts/validate_clickhouse_schema.rb
