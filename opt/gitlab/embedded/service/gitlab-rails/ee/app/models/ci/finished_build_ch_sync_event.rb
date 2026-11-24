# frozen_string_literal: true

module Ci
  class FinishedBuildChSyncEvent < Ci::ApplicationRecord
    include PartitionedTable

    PARTITION_DURATION = 1.day
    PARTITION_CLEANUP_THRESHOLD = 30.days

    self.table_name = :p_ci_finished_build_ch_sync_events
    self.primary_key = :build_id

    ignore_columns :partition, remove_never: true

    partitioned_by :partition, strategy: :sliding_list,
      next_partition_if: ->(active_partition) { any_older_partitions_exist?(active_partition, PARTITION_DURATION) },
      detach_partition_if: ->(partition) { detach_partition?(partition) }

    belongs_to :build, class_name: 'Ci::Build'

    validates :project_id, presence: true
    validates :build_id, presence: true
    validates :build_finished_at, presence: true

    scope :order_by_build_id, -> { order(:build_id) }

    scope :pending, -> { where(processed: false) }
    scope :for_partition, ->(partition) { where(partition: partition) }

    def self.upsert_from_build(build)
      upsert({ build_id: build.id, project_id: build.project_id, build_finished_at: build.finished_at },
        unique_by: [:build_id, :partition])
    end

    def self.detach_partition?(partition)
      # detach partition if there are no pending events in partition
      return true unless pending.for_partition(partition.value).exists?

      # or if there are pending events, they are outside the cleanup threshold
      return true unless any_newer_partitions_exist?(partition, PARTITION_CLEANUP_THRESHOLD)

      false
    end

    def self.any_older_partitions_exist?(partition, duration)
      for_partition(partition.value)
        .where(arel_table[:build_finished_at].lteq(duration.ago))
        .exists?
    end

    def self.any_newer_partitions_exist?(partition, duration)
      for_partition(partition.value)
        .where(arel_table[:build_finished_at].gt(duration.ago))
        .exists?
    end
  end
end
