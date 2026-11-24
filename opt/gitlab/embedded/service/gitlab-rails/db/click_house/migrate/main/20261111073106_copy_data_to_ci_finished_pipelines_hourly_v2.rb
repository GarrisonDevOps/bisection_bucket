# frozen_string_literal: true

class CopyDataToCiFinishedPipelinesHourlyV2 < ClickHouse::Migration
  BATCH_SIZE = 1_000_000

  PRIMARY_KEYS = %i[started_at_bucket path status source ref].freeze

  COLUMNS = %i[
    path
    status
    source
    ref
    name
    started_at_bucket
    count_pipelines
    duration_quantile
  ].freeze

  def up
    # Makes retries idempotent: re-inserting aggregate states would double the counts.
    execute 'TRUNCATE TABLE IF EXISTS ci_finished_pipelines_hourly_v2'

    iterator = ClickHouse::TableIterator.new(
      'ci_finished_pipelines_hourly',
      primary_keys: PRIMARY_KEYS,
      connection: connection
    )

    iterator.each_range(of: BATCH_SIZE) do |scope|
      execute(
        "INSERT INTO ci_finished_pipelines_hourly_v2 (#{COLUMNS.join(', ')}) #{scope.select(*COLUMNS).to_sql}"
      )
    end
  end

  def down; end
end
