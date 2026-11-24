# frozen_string_literal: true

module Mutations
  module ComplianceManagement
    module Frameworks
      class Create < BaseMutation
        graphql_name 'CreateComplianceFramework'

        authorize_granular_token permissions: :create_compliance_framework,
          boundary_argument: :namespace_path, boundary: :root_ancestor, boundary_type: :group

        field :framework,
          Types::ComplianceManagement::ComplianceFrameworkType,
          null: true,
          description: 'Created compliance framework.'

        argument :namespace_path, GraphQL::Types::ID,
          required: true,
          description: 'Full path of the namespace to add the compliance framework to.'

        argument :params, Types::ComplianceManagement::ComplianceFrameworkInputType,
          required: true,
          description: 'Parameters to update the compliance framework with.'

        def resolve(**args)
          group = namespace(args[:namespace_path])

          raise_resource_not_available_error! unless group

          service = ::ComplianceManagement::Frameworks::CreateService.new(namespace: group,
            params: args[:params].to_h,
            current_user: current_user).execute

          service.success? ? success(service) : error(service)
        end

        private

        def success(service)
          { framework: service.payload[:framework], errors: [] }
        end

        def error(service)
          errors = [service.message]
          model_errors = service.payload.try(:full_messages).to_a

          { errors: (errors + model_errors).flatten }
        end

        def namespace(namespace_path)
          ::Gitlab::Graphql::Loaders::FullPathModelLoader.new(::Namespace, namespace_path).find.sync
        end
      end
    end
  end
end
