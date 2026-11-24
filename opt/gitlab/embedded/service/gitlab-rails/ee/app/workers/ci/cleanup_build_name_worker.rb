# frozen_string_literal: true

module Ci
  class CleanupBuildNameWorker
    include ApplicationWorker
    include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- does not perform work scoped to a context

    urgency :throttled
    idempotent!
    deduplicate :until_executed
    feature_category :continuous_integration
    data_consistency :sticky
    concurrency_limit -> { 1 }
    defer_on_database_health_signal :gitlab_ci, [:p_ci_build_names], 10.minutes

    def perform
      partitions_to_truncate.each do |partition|
        partition_table_name = partition.fully_qualified_partition

        Ci::ApplicationRecord.connection.execute("TRUNCATE TABLE #{partition_table_name}")
      end
    end

    private

    # We skip the current partition and the most recent active partition
    # rubocop:disable CodeReuse/ActiveRecord -- specialized partition queries not suitable on model level
    def partitions_to_truncate
      old_partition_ids = Ci::Partition.with_status(:active).order(id: :desc).offset(1).pluck(:id)

      Gitlab::Database::SharedModel.using_connection(Ci::ApplicationRecord.connection) do
        Ci::BuildName.partitioning_strategy.current_partitions
          .select { |partition| (partition.values - old_partition_ids).empty? }
          .select { |partition| Ci::BuildName.in_partition(partition.values).any? }
      end
    end
    # rubocop:enable CodeReuse/ActiveRecord
  end
end
