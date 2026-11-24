# frozen_string_literal: true

module Mutations
  module ComplianceManagement
    module Projects
      module ComplianceViolations
        class Update < ::Mutations::BaseMutation
          graphql_name 'UpdateProjectComplianceViolation'

          authorize :update_compliance_violations_report
          authorize_granular_token permissions: :update_compliance_violations_report,
            boundary_argument: :id, boundary: :project, boundary_type: :project

          argument :id,
            ::Types::GlobalIDType[::ComplianceManagement::Projects::ComplianceViolation],
            required: true,
            description: 'Global ID of the project compliance violation to update.'

          argument :status, ::Types::ComplianceManagement::Projects::ComplianceViolationStatusEnum,
            required: true,
            description: 'New status for the project compliance violation.'

          field :compliance_violation,
            ::Types::ComplianceManagement::Projects::ComplianceViolationType,
            null: true,
            description: "Compliance violation after status update."

          def resolve(id:, **args)
            violation = authorized_find!(id: id)

            if violation.update(status: args[:status])
              audit_event(violation)

              create_system_note(violation)
            end

            { compliance_violation: violation, errors: errors_on_object(violation) }
          end

          private

          def create_system_note(violation)
            old_status = violation.status_before_last_save
            new_status = violation.status

            return if old_status == new_status

            ::SystemNotes::ComplianceViolationsService.new(
              container: violation.project,
              noteable: violation,
              author: current_user).change_violation_status
          end

          def audit_event(violation)
            old_status = violation.status_before_last_save
            new_status = violation.status

            return if old_status == new_status

            audit_context = {
              name: 'update_project_compliance_violation',
              author: current_user,
              scope: violation.project,
              target: violation,
              message: "Changed project compliance violation's status from #{old_status} to #{new_status}",
              additional_details: {
                old_status: old_status,
                new_status: new_status
              }
            }

            ::Gitlab::Audit::Auditor.audit(audit_context)
          end
        end
      end
    end
  end
end
