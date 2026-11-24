# frozen_string_literal: true

module ComplianceManagement
  module ComplianceFramework
    module ComplianceRequirements
      class CreateService < BaseRequirementsService
        def initialize(framework:, params:, current_user:, controls: [])
          @framework = framework
          @params = params
          @current_user = current_user
          @requirement = ComplianceManagement::ComplianceFramework::ComplianceRequirement.new
          @controls = controls || []
        end

        def execute
          return ServiceResponse.error(message: _('Not permitted to create requirement')) unless permitted?
          return control_limit_error if control_count_exceeded?

          begin
            ComplianceManagement::ComplianceFramework::ComplianceRequirement.transaction do
              create_requirement

              add_controls
            end
          rescue ActiveRecord::RecordInvalid
            return error
          rescue InvalidControlError => e
            return ServiceResponse.error(message: e.message, payload: e.message)
          end

          enqueue_project_framework_evaluation
          audit_create

          success
        end

        private

        attr_reader :params, :current_user, :framework, :requirement, :controls

        def permitted?
          can? current_user, :admin_compliance_framework, framework
        end

        def create_requirement
          assign_requirement_attributes
          requirement.save!
        end

        def assign_requirement_attributes
          requirement.assign_attributes(
            framework: framework,
            namespace_id: framework.namespace.id,
            name: params[:name],
            description: params[:description]
          )
        end

        def audit_create
          audit_context = {
            name: 'created_compliance_requirement',
            author: current_user,
            scope: framework.namespace,
            target: requirement,
            message: "Created compliance requirement #{requirement.name} for framework #{framework.name}"
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end

        def error
          ServiceResponse.error(message: _('Failed to create compliance requirement'), payload: requirement.errors)
        end
      end
    end
  end
end
