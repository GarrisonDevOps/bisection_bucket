# frozen_string_literal: true

module Mutations
  module ComplianceManagement
    module ComplianceFramework
      module ComplianceRequirementsControls
        class Update < BaseMutation
          graphql_name 'UpdateComplianceRequirementsControl'

          authorize :admin_compliance_framework
          authorize_granular_token permissions: :update_compliance_requirements_control,
            boundary_argument: :id, boundary: :namespace, boundary_type: :group

          argument :id,
            ::Types::GlobalIDType[::ComplianceManagement::ComplianceFramework::ComplianceRequirementsControl],
            required: true,
            description: 'Global ID of the compliance requirement control to update.'

          argument :params, Types::ComplianceManagement::ComplianceRequirementsControlInputType,
            required: true,
            description: 'Parameters to update the compliance requirement control with.'

          field :requirements_control,
            Types::ComplianceManagement::ComplianceRequirementsControlType,
            null: true,
            description: 'Compliance requirement control after updation.'

          def resolve(id:, **args)
            requirements_control = authorized_find!(id: id)

            result = ::ComplianceManagement::ComplianceFramework::ComplianceRequirementsControls::UpdateService.new(
              control: requirements_control,
              current_user: current_user,
              params: args[:params].to_h).execute

            { requirements_control: requirements_control, errors: result.success? ? [] : Array.wrap(result.message) }
          end
        end
      end
    end
  end
end
