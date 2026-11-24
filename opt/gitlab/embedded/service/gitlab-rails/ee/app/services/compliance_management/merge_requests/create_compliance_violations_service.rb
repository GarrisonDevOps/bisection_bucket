# frozen_string_literal: true

module ComplianceManagement
  module MergeRequests
    class CreateComplianceViolationsService < ComplianceManagement::MergeRequests::BaseService
      def execute
        return ServiceResponse.error(message: _('This group is not permitted to create compliance violations')) unless permitted?(@merge_request.target_project.namespace)
        return ServiceResponse.error(message: _('Merge request not merged')) unless @merge_request.merged?

        # Skip violation checks for MRs that were auto-transitioned to merged because
        # another MR already introduced the same commits. The code was reviewed and
        # approved on that other MR, so flagging this one would be a false positive.
        return ServiceResponse.success(message: _('Merge request merged via another merge request, skipping compliance violations')) if merged_via_another_merge_request?

        ::MergeRequests::ComplianceViolation.process_merge_request(@merge_request)

        ServiceResponse.success(message: _('Created compliance violations if any were found'))
      end

      private

      def permitted?(group)
        group.licensed_feature_available?(:group_level_compliance_dashboard)
      end

      def merged_via_another_merge_request?
        @merge_request.resource_state_events.merged_by_another_merge_request.exists?
      end
    end
  end
end
