# frozen_string_literal: true

module Ci
  module TestBalancing
    class Assignment < Ci::ApplicationRecord
      include PartitionedTable

      RETENTION_PERIOD = 7.days

      partitioned_by :pipeline_created_at, strategy: :daily, retain_for: RETENTION_PERIOD

      belongs_to :project
      belongs_to :pipeline, class_name: 'Ci::Pipeline'
      belongs_to :test_split, class_name: 'Ci::TestBalancing::TestSplit'
      belongs_to :job_group, class_name: 'Ci::TestBalancing::JobGroup'

      # Returns an array of test split paths with their expected durations.
      #
      # Example:
      # [
      #   { path: <test path 1>, expected_duration: <duration 1> },
      #   { path: <test path 2>, expected_duration: <duration 2> },
      # ]
      def self.test_splits_for_node(pipeline, job_group, node_index)
        where(
          project_id: pipeline.project_id,
          pipeline_id: pipeline.id,
          pipeline_created_at: pipeline.created_at,
          job_group_id: job_group.id,
          node_index: node_index
        )
          .joins(:test_split)
          .order(expected_duration: :desc)
          .limit(MAX_TEST_SPLITS_PER_JOB_GROUP)
          .pluck(:path, :expected_duration)
          .map { |path, duration| { path: path, expected_duration: duration } }
      end
    end
  end
end
