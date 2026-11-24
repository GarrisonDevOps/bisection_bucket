# frozen_string_literal: true

module Ci
  # Counts a runner's jobs for offset pagination, reading `p_ci_builds` partitions newest first
  class RunnerJobsCounter
    def initialize(limit: Kaminari::ActiveRecordRelationMethods::MAX_COUNT_LIMIT)
      @limit = limit
    end

    # @param jobs [ActiveRecord::Relation] the paginated runner jobs
    # @return [Integer] the number of jobs, up to `limit` + 1
    def call(jobs)
      # Partitions 100 to 102 have no row until `Ci::PartitioningWorker` first runs
      return jobs.total_count_with_limit(:all, limit: limit) unless Ci::Partition.exists?

      newest_partitions_first_count(jobs)
    end

    private

    attr_reader :limit

    # rubocop: disable CodeReuse/ActiveRecord -- requires a specialized query to read partitions newest first
    def newest_partitions_first_count(jobs)
      Ci::Partition
        .joins("CROSS JOIN LATERAL (#{jobs_in_partition(jobs).to_sql}) jobs")
        .order(id: :desc)
        .limit(limit + 1)
        .count
    end

    def jobs_in_partition(jobs)
      jobs
        .except(:offset, :limit, :order)
        .where(Ci::Build.arel_table[:partition_id].eq(Ci::Partition.arel_table[:id]))
        .select(1)
        .limit(limit + 1)
    end
    # rubocop: enable CodeReuse/ActiveRecord
  end
end
