# frozen_string_literal: true

module EE
  module MergeRequests
    module ReloadMergeHeadDiffService
      extend ::Gitlab::Utils::Override

      override :execute
      def execute
        super.tap do |response|
          next unless response[:status] == :success
          next unless merge_request.project.licensed_feature_available?(:code_owners)
          next if merge_request.on_train?

          sync_code_owner_approval_rules

          enqueue_pending_auto_reviewer_assignment
        end
      end

      private

      def sync_code_owner_approval_rules
        ::MergeRequests::SyncCodeOwnerApprovalRules.new(merge_request).execute
      end

      def enqueue_pending_auto_reviewer_assignment
        return unless ::MergeRequests::ReviewerAssignment::PendingInitialAssignment.consume(merge_request)

        ::MergeRequests::AutoAssignReviewersWorker.perform_async(merge_request.id)
      end
    end
  end
end
