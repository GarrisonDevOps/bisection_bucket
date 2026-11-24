# frozen_string_literal: true

module Geo
  # Recalculates verification state counts for dirty buckets in the
  # geo_ci_job_artifact_verification_summaries table.
  #
  # Each bucket represents a modulo-based slice of ci_job_artifact_states rows.
  # Only buckets marked as dirty are processed. In steady state this is a small
  # fraction of the 100k total buckets.
  #
  # Called by Geo::CiJobArtifactVerificationSummaryCalculatorWorker on a cron schedule.
  #
  # rubocop:disable CodeReuse/ActiveRecord -- Service encapsulates specific query logic for bucket recalculation
  class CiJobArtifactVerificationSummaryCalculatorService
    include Gitlab::Utils::StrongMemoize

    DIRTY_BUCKET_LIMIT = 100
    CALCULATING_TIMEOUT = 10.minutes

    def execute
      return { buckets_calculated: 0 } unless Gitlab::Geo.enabled?

      @bucket_numbers = claim_buckets
      return { buckets_calculated: 0 } if @bucket_numbers.empty?

      count_dirty_buckets
      update_summary_counts

      { buckets_calculated: @bucket_numbers.size }
    end

    private

    def now
      Time.current
    end
    strong_memoize_attr :now

    # Atomically selects and claims dirty/stuck buckets in a single query.
    # Transitions them to calculating state and returns the claimed bucket numbers.
    #
    # @return [Array<Integer>] bucket numbers claimed for recalculation
    def claim_buckets
      table = CiJobArtifactVerificationSummary.table_name
      calculating = CiJobArtifactVerificationSummary.states[:calculating]
      quoted_now = connection.quote(now)

      eligible_sql = CiJobArtifactVerificationSummary
        .needs_recalculation(CALCULATING_TIMEOUT)
        .state_changed_asc
        .limit(DIRTY_BUCKET_LIMIT)
        .select(:bucket_number)
        .to_sql

      sql = <<~SQL.squish
        UPDATE #{table} AS summaries
        SET state = #{calculating}, state_changed_at = #{quoted_now}
        FROM (#{eligible_sql}) AS eligible
        WHERE summaries.bucket_number = eligible.bucket_number
        RETURNING summaries.bucket_number
      SQL

      connection.exec_query(sql).rows.flatten
    end

    # Queries ci_job_artifact_states for the claimed buckets and stores the
    # aggregated counts (total, verified, failed) grouped by bucket number.
    def count_dirty_buckets
      bucket_count = CiJobArtifactVerificationSummary::BUCKET_COUNT

      rows = JobArtifactState
        .where("job_artifact_id % ? IN (?)", bucket_count, @bucket_numbers)
        .select(
          Arel.sql("job_artifact_id % #{bucket_count} AS bucket_number"),
          Arel.sql("COUNT(*) AS total_count"),
          Arel.sql("COUNT(*) FILTER (WHERE verification_state = #{verification_succeeded_value}) AS verified_count"),
          Arel.sql("COUNT(*) FILTER (WHERE verification_state = #{verification_failed_value}) AS failed_count")
        )
        .group(Arel.sql("job_artifact_id % #{bucket_count}"))

      @counts_by_bucket = rows.each_with_object({}) do |row, hash|
        hash[row.bucket_number] = {
          total: row.total_count,
          verified: row.verified_count,
          failed: row.failed_count
        }
      end
    end

    # Writes recalculated counts and marks buckets as clean in a single query.
    # Only updates buckets still in the calculating state to avoid overwriting
    # buckets re-dirtied by the DB trigger during calculation.
    def update_summary_counts
      table = CiJobArtifactVerificationSummary.table_name
      clean = CiJobArtifactVerificationSummary.states[:clean]
      calculating = CiJobArtifactVerificationSummary.states[:calculating]
      quoted_now = connection.quote(now)

      values = @bucket_numbers.map do |bucket_number|
        counts = @counts_by_bucket.fetch(bucket_number, { total: 0, verified: 0, failed: 0 })
        "(#{bucket_number}, #{counts[:total]}, #{counts[:verified]}, #{counts[:failed]})"
      end

      sql = <<~SQL.squish
        UPDATE #{table} AS summaries
        SET total_count = data.total,
            verified_count = data.verified,
            failed_count = data.failed,
            state = #{clean},
            state_changed_at = #{quoted_now},
            last_calculated_at = #{quoted_now},
            updated_at = #{quoted_now}
        FROM (VALUES #{values.join(', ')}) AS data(bucket_number, total, verified, failed)
        WHERE summaries.bucket_number = data.bucket_number
          AND summaries.state = #{calculating}
      SQL

      connection.execute(sql)
    end

    def connection
      CiJobArtifactVerificationSummary.connection
    end

    def verification_succeeded_value
      Geo::VerificationState::VERIFICATION_STATE_VALUES[:verification_succeeded]
    end

    def verification_failed_value
      Geo::VerificationState::VERIFICATION_STATE_VALUES[:verification_failed]
    end
  end
  # rubocop:enable CodeReuse/ActiveRecord
end
