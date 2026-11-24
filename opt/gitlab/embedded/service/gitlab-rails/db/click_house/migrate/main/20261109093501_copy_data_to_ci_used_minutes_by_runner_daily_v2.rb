# frozen_string_literal: true

class CopyDataToCiUsedMinutesByRunnerDailyV2 < ClickHouse::Migration
  BATCH_SIZE = 500_000

  PRIMARY_KEYS = %i[finished_at_bucket runner_type status runner_id].freeze

  COLUMNS = %i[
    finished_at_bucket
    runner_type
    status
    runner_id
    project_id
    count_builds
    total_duration
  ].freeze

  def up
    # Makes retries idempotent: re-inserting aggregate states would double the counts.
    execute 'TRUNCATE TABLE IF EXISTS ci_used_minutes_by_runner_daily_v2'

    iterator = ClickHouse::TableIterator.new(
      'ci_used_minutes_by_runner_daily',
      primary_keys: PRIMARY_KEYS,
      connection: connection
    )

    iterator.each_range(of: BATCH_SIZE) do |scope|
      execute(
        "INSERT INTO ci_used_minutes_by_runner_daily_v2 (#{COLUMNS.join(', ')}) #{scope.select(*COLUMNS).to_sql}"
      )
    end
  end

  def down; end
end
