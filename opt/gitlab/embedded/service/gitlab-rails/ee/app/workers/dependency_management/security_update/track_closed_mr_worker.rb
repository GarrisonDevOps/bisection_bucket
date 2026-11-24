# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    class TrackClosedMrWorker
      include TracksAutoRemediationMrEvent

      idempotent!

      EVENT_NAME = 'close_dependency_management_auto_remediation_mr'

      private

      # Only a close by someone other than the bot counts. A wrong dismissal
      # silently stops remediating, while a wrong re-proposal costs one merge request.
      def remediation_state_for(merge_request)
        # Jobs can run out of order, and latest_closed_by_id survives a reopen.
        return unless merge_request.closed?

        closer_id = merge_request.metrics&.latest_closed_by_id

        # No closer, or the bot closing its own. not_closed_by skips both.
        return if closer_id.nil?
        return if closer_id == merge_request.project.dependency_management_service_account&.id

        # Deleting the branch closes the merge request as a side effect, so this
        # is cleanup rather than a decision. Re-proposing recreates the branch.
        return unless merge_request.source_branch_exists?

        :dismissed
      end
    end
  end
end
