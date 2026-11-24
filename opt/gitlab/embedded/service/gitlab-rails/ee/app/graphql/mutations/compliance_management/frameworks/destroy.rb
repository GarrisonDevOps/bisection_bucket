# frozen_string_literal: true

module Mutations
  module ComplianceManagement
    module Frameworks
      class Destroy < ::Mutations::BaseMutation
        graphql_name 'DestroyComplianceFramework'

        authorize :admin_compliance_framework
        authorize_granular_token permissions: :delete_compliance_framework,
          boundary_argument: :id, boundary: :namespace, boundary_type: :group

        argument :id,
          ::Types::GlobalIDType[::ComplianceManagement::Framework],
          required: true,
          description: 'Global ID of the compliance framework to destroy.'

        def resolve(id:)
          framework = authorized_find!(id: id)
          result = ::ComplianceManagement::Frameworks::DestroyService.new(framework: framework, current_user: current_user).execute

          { errors: result.success? ? [] : Array.wrap(result.message) }
        end
      end
    end
  end
end
