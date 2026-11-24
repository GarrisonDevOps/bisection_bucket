# frozen_string_literal: true

module MergeRequests
  module ReviewerAssignment
    # Tracks a one-shot intent to auto-assign reviewers on a newly-created merge request.
    #
    # The flag is set in EE::MergeRequests::CreateService#after_create and
    # consumed by EE::MergeRequests::ReloadMergeHeadDiffService once the
    # merge head diff has been (re)built and code-owner approval rules
    # have been re-synced against it. This avoids racing against the
    # initial sync, which would otherwise enqueue AutoAssignReviewersWorker
    # before any code-owner rules exist for the diff.
    module PendingInitialAssignment
      TTL = 10.minutes

      def self.mark(merge_request)
        Gitlab::Redis::SharedState.with do |redis|
          redis.set(key(merge_request.id), 1, ex: TTL.to_i, nx: true)
        end
      end

      def self.consume(merge_request)
        Gitlab::Redis::SharedState.with do |redis|
          redis.del(key(merge_request.id)) == 1
        end
      end

      def self.key(merge_request_id)
        "merge_requests:pending_initial_auto_assign:#{merge_request_id}"
      end
    end
  end
end
