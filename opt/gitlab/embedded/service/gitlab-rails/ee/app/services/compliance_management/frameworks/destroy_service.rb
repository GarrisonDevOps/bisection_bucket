# frozen_string_literal: true

module ComplianceManagement
  module Frameworks
    class DestroyService < BaseService
      attr_reader :framework, :current_user

      def initialize(framework:, current_user:)
        @framework = framework
        @current_user = current_user
      end

      def execute
        return ServiceResponse.error(message: _('Not permitted to destroy framework')) unless permitted?
        return ServiceResponse.error(message: _('Cannot delete the default framework')) if default_framework?
        return linked_to_security_policy_error if framework.linked_to_security_policy?

        framework.destroy ? success : error
      end

      private

      def linked_to_security_policy_error
        ServiceResponse.error(
          message: _('Cannot delete the compliance framework because it is referenced by a security policy. ' \
            'Remove it from the policy scope first.'),
          reason: :linked_to_security_policy
        )
      end

      def permitted?
        can? current_user, :admin_compliance_framework, framework
      end

      def success
        audit_destroy

        enqueue_project_settings_deletion_worker if framework_belongs_to_csp_group?

        ServiceResponse.success(message: _('Framework successfully deleted'))
      end

      def framework_belongs_to_csp_group?
        ::Security::PolicySetting.in_organization(
          framework.namespace.organization
        )&.csp_namespace_id == framework.namespace_id
      end

      def enqueue_project_settings_deletion_worker
        ComplianceManagement::ProjectSettingsDestroyWorker.perform_async(nil, framework.id)
      end

      def error
        ServiceResponse.error(message: _('Failed to create framework'), payload: framework.errors)
      end

      def audit_destroy
        audit_context = {
          name: 'destroy_compliance_framework',
          author: current_user,
          scope: framework.namespace,
          target: framework,
          message: %(Destroyed compliance framework: "#{framework.name}")
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      def default_framework?
        framework.id == framework.namespace.namespace_settings.default_compliance_framework_id
      end
    end
  end
end
