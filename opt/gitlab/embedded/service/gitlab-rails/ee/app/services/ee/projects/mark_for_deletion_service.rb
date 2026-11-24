# frozen_string_literal: true

module EE
  module Projects
    module MarkForDeletionService
      extend ::Gitlab::Utils::Override
      include SecurityOrchestrationHelper

      LinkedAsSecurityPolicyProjectError = ServiceResponse.error(
        message: 'Project cannot be deleted because it is linked as a security policy project')

      private

      override :preconditions_checks
      def preconditions_checks
        result = super
        return result if result.error?
        return LinkedAsSecurityPolicyProjectError if reject_security_policy_project_deletion?

        ServiceResponse.success
      end

      def reject_security_policy_project_deletion?
        security_configurations_preventing_project_deletion(resource).exists?
      end

      override :extra_log_audit_event_context
      def extra_log_audit_event_context
        {
          additional_details: {
            project_id: resource.id,
            namespace_id: resource.namespace_id,
            root_namespace_id: resource.root_namespace.id
          }
        }
      end
    end
  end
end
