# frozen_string_literal: true

module Mutations
  module ComplianceManagement
    module ComplianceFramework
      module ComplianceRequirements
        class Destroy < BaseMutation
          graphql_name 'DestroyComplianceRequirement'
          authorize :admin_compliance_framework
          authorize_granular_token permissions: :delete_compliance_requirement,
            boundary_argument: :id, boundary: :namespace, boundary_type: :group

          argument :id, ::Types::GlobalIDType[::ComplianceManagement::ComplianceFramework::ComplianceRequirement],
            required: true,
            description: 'Global ID of the compliance requirement to destroy.'

          def resolve(id:)
            requirement = authorized_find!(id: id)

            result = ::ComplianceManagement::ComplianceFramework::ComplianceRequirements::DestroyService.new(
              requirement: requirement, current_user: current_user).execute

            { errors: result.success? ? [] : Array.wrap(result.message) }
          end
        end
      end
    end
  end
end
