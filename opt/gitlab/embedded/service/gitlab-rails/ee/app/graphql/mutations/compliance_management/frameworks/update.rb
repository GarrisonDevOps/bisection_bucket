# frozen_string_literal: true

module Mutations
  module ComplianceManagement
    module Frameworks
      class Update < ::Mutations::BaseMutation
        graphql_name 'UpdateComplianceFramework'

        authorize :admin_compliance_framework
        authorize_granular_token permissions: :update_compliance_framework,
          boundary_argument: :id, boundary: :namespace, boundary_type: :group

        argument :id,
          ::Types::GlobalIDType[::ComplianceManagement::Framework],
          required: true,
          description: 'Global ID of the compliance framework to update.'

        argument :params, Types::ComplianceManagement::ComplianceFrameworkInputType,
          required: true,
          description: 'Parameters to update the compliance framework with.'

        field :compliance_framework,
          Types::ComplianceManagement::ComplianceFrameworkType,
          null: true,
          description: "Compliance framework after mutation."

        def resolve(id:, **args)
          framework = authorized_find!(id: id)
          ::ComplianceManagement::Frameworks::UpdateService.new(framework: framework,
            current_user: current_user,
            params: args[:params].to_h).execute
          { compliance_framework: framework, errors: errors_on_object(framework) }
        end
      end
    end
  end
end
