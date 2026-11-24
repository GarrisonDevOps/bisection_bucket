# frozen_string_literal: true

module Mutations
  module ComplianceManagement
    module ComplianceFramework
      module ComplianceRequirements
        class Update < BaseMutation
          graphql_name 'UpdateComplianceRequirement'
          authorize :admin_compliance_framework
          authorize_granular_token permissions: :update_compliance_requirement,
            boundary_argument: :id, boundary: :namespace, boundary_type: :group

          argument :id, ::Types::GlobalIDType[::ComplianceManagement::ComplianceFramework::ComplianceRequirement],
            required: true,
            description: 'Global ID of the compliance requirement to update.'

          argument :params, Types::ComplianceManagement::ComplianceRequirementInputType,
            required: true,
            description: 'Parameters to update the compliance requirement with.'

          argument :controls,
            [::Types::ComplianceManagement::ComplianceRequirementsControlInputType],
            required: false,
            description: 'Controls to add or update to the compliance requirement.'

          field :requirement,
            Types::ComplianceManagement::ComplianceRequirementType,
            null: true,
            description: 'Compliance requirement after updation.'

          def resolve(id:, **args)
            requirement = authorized_find!(id: id)

            response = ::ComplianceManagement::ComplianceFramework::ComplianceRequirements::UpdateService.new(
              requirement: requirement,
              current_user: current_user,
              params: args[:params].to_h,
              controls: args[:controls]
            ).execute

            response.success? ? success(requirement) : error(response, requirement)
          end

          def success(requirement)
            { requirement: requirement, errors: [] }
          end

          def error(response, requirement)
            errors = [response.message]
            model_errors = errors_on_object(requirement).to_a

            { requirement: requirement, errors: (errors + model_errors).flatten }
          end
        end
      end
    end
  end
end
