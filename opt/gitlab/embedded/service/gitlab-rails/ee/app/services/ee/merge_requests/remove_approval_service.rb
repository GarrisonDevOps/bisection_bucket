# frozen_string_literal: true

module EE
  module MergeRequests
    module RemoveApprovalService
      extend ::Gitlab::Utils::Override

      private

      override :reset_approvals_cache
      def reset_approvals_cache(merge_request)
        merge_request.reset_approval_cache!
      end

      override :trigger_approval_hooks
      def trigger_approval_hooks(merge_request, skip_notification)
        # Capture the approval state BEFORE removing the approval
        was_approved = merge_request.approved?

        yield

        return if skip_notification

        # Check the approval state AFTER removing the approval
        is_currently_approved = merge_request.approved?

        # Only send notification if MR was approved before removal
        notification_service.async.unapprove_mr(merge_request, current_user) if was_approved

        # Only send 'unapproved' if the MR transitioned from approved to not approved
        if was_approved && !is_currently_approved
          execute_hooks(merge_request, 'unapproved')
        else
          # Send 'unapproval' for individual approval removal that doesn't change overall approval state
          execute_hooks(merge_request, 'unapproval')
        end
      end
    end
  end
end
