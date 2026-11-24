# frozen_string_literal: true

module Ci
  module TestBalancing
    # Prepares the Redis pending queue for a node at the start of a parallel job.
    #
    # If the node already has claimed tests (job retry or crash recovery),
    # those are replayed unchanged. Otherwise, the caller's static test split is
    # seeded into the shared queue.
    class InitializeService < BaseService
      BATCH_SIZE = 500

      def execute(test_splits)
        error = validate_preconditions
        return error if error

        test_splits_to_replay = claimed_test_splits

        if test_splits_to_replay.empty?
          return too_many_tests_response unless within_limit?(test_splits)

          seed_queue(test_splits)
        end

        ServiceResponse.success(payload: { test_splits_to_replay: test_splits_to_replay })
      rescue ActiveRecord::RecordInvalid => e
        ServiceResponse.error(message: e.message, reason: :invalid_tests)
      end

      private

      def claimed_test_splits
        recover_backup

        ::Ci::TestBalancing::Assignment
          .test_splits_for_node(job.pipeline, job_group, node_index)
      end

      def within_limit?(test_splits)
        queue.size + test_splits.size <= MAX_TEST_SPLITS_PER_JOB_GROUP
      end

      def too_many_tests_response
        ServiceResponse.error(
          message: "Number of tests exceeds the limit of #{MAX_TEST_SPLITS_PER_JOB_GROUP} per job group",
          reason: :invalid_tests
        )
      end

      def seed_queue(test_splits)
        test_splits.each_slice(BATCH_SIZE) do |batch|
          queue.seed(convert_paths_to_ids(batch))
        end
      end

      def convert_paths_to_ids(items)
        paths = items.pluck(:path) # rubocop:disable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit -- plain Array, not AR
        ids = ::Ci::TestBalancing::TestSplit.fetch_or_create_ids!(job.project_id, paths)

        items.map do |item|
          { test_split_id: ids[item[:path]], expected_duration: item[:expected_duration] }
        end
      end
    end
  end
end
