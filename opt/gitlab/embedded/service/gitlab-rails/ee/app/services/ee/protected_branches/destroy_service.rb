# frozen_string_literal: true

module EE
  module ProtectedBranches
    module DestroyService
      extend ::Gitlab::Utils::Override
      include Loggable

      override :execute
      def execute(protected_branch, skip_authorization: false, skip_rate_limit: false)
        raise ::Gitlab::Access::AccessDeniedError if blocked_by_scan_result_policy?(protected_branch)

        super.tap do |protected_branch_service|
          # DestroyService returns the value of #.destroy instead of the
          # instance, in comparison with the other services
          # (CreateService and UpdateService) so if the destroy service
          # doesn't succeed the value will be false instead of an instance
          log_audit_event(protected_branch_service, :remove) if protected_branch_service
        end
      end

      private

      def blocked_by_scan_result_policy?(protected_branch)
        return blocked_on_project_level?(protected_branch) if protected_branch.project_level?

        blocked_on_group_level?(protected_branch)
      end

      def blocked_on_project_level?(protected_branch)
        project = protected_branch.project

        return false unless ::Security::PolicyAvailability.any_available?(project)

        service = ::Security::SecurityOrchestrationPolicies::ProtectedBranchesDeletionCheckService.new(
          project: project, current_user: current_user)
        protected_from_deletion = service.execute([protected_branch])

        protected_branch.in?(protected_from_deletion)
      end

      def blocked_on_group_level?(protected_branch)
        ::Security::SecurityOrchestrationPolicies::GroupProtectedBranchesDeletionCheckService
          .new(group: protected_branch.group, current_user: current_user)
          .execute
      end
    end
  end
end
