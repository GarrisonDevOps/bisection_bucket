# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    module ComplianceRequirementsControls
      class CreateService < BaseService
        attr_reader :params, :current_user, :requirement, :control

        DEFAULT_CONTROL_TYPE = 'internal'

        def initialize(requirement:, params:, current_user:)
          @requirement = requirement
          @params = params
          @current_user = current_user
          @control = ComplianceManagement::ComplianceFramework::ComplianceRequirementsControl.new
        end

        def execute
          return ServiceResponse.error(message: _('Not permitted to create compliance control')) unless permitted?

          control.assign_attributes(
            compliance_requirement: requirement,
            namespace_id: requirement.namespace.id,
            name: params[:name],
            expression: params[:expression],
            control_type: params[:control_type] || DEFAULT_CONTROL_TYPE,
            external_control_name: params[:external_control_name],
            external_url: params[:external_url],
            secret_token: params[:secret_token],
            ping_enabled: params.fetch(:ping_enabled, true)
          )

          return error unless control.save

          audit_create
          success
        end

        private

        def permitted?
          can?(current_user, :admin_compliance_framework, requirement.framework)
        end

        def success
          ServiceResponse.success(payload: { control: control })
        end

        def audit_create
          audit_context = {
            name: 'created_compliance_requirement_control',
            author: current_user,
            scope: requirement.namespace,
            target: control,
            message: "Created compliance control #{control.name} for requirement #{requirement.name}",
            additional_details: {
              framework: requirement.framework.name,
              control_type: control.control_type
            }
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end

        def error
          ServiceResponse.error(message: _('Failed to create compliance requirement control'), payload: control.errors)
        end
      end
    end
  end
end
