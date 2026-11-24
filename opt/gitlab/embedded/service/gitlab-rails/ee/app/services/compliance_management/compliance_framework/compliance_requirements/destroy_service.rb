# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    module ComplianceRequirements
      class DestroyService < BaseService
        attr_reader :current_user, :requirement

        def initialize(requirement:, current_user:)
          @requirement = requirement
          @current_user = current_user
        end

        def execute
          return ServiceResponse.error(message: _('Not permitted to destroy requirement')) unless permitted?

          requirement.destroy ? success : error
        end

        private

        def permitted?
          can? current_user, :admin_compliance_framework, requirement.framework
        end

        def success
          audit_destroy

          ServiceResponse.success(message: _('Compliance requirement successfully deleted'))
        end

        def audit_destroy
          audit_context = {
            name: 'destroyed_compliance_requirement',
            author: current_user,
            scope: requirement.framework.namespace,
            target: requirement,
            message: "Destroyed compliance requirement #{requirement.name}"
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end

        def error
          ServiceResponse.error(message: _('Failed to destroy compliance requirement'), payload: requirement.errors)
        end
      end
    end
  end
end
