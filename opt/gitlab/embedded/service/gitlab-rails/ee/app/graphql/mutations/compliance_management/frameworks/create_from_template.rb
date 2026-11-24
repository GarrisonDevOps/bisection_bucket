# frozen_string_literal: true

module Mutations
  module ComplianceManagement
    module Frameworks
      class CreateFromTemplate < BaseMutation
        graphql_name 'CreateComplianceFrameworkFromTemplate'

        authorize :admin_compliance_framework
        authorize_granular_token permissions: :create_compliance_framework,
          boundary_argument: :namespace_path, boundary_type: :group

        field :framework,
          Types::ComplianceManagement::ComplianceFrameworkType,
          null: true,
          description: 'Created compliance framework.'

        argument :namespace_path, GraphQL::Types::ID,
          required: true,
          description: 'Full path of the namespace to add the compliance framework to.'

        argument :template_id,
          ::Types::GlobalIDType[::ComplianceManagement::Frameworks::TemplateRegistry::Template],
          required: true,
          description: 'Unique identifier of the template to create the framework from.'

        argument :name, GraphQL::Types::String,
          required: false,
          description: 'Override the name of the compliance framework.'

        argument :description, GraphQL::Types::String,
          required: false,
          description: 'Override the description of the compliance framework.'

        argument :color, GraphQL::Types::String,
          required: false,
          description: 'Override the color of the compliance framework in hex format. e.g. #FCA121.'

        argument :default, GraphQL::Types::Boolean,
          required: false,
          description: 'Set the compliance framework as the default framework for the group.'

        def resolve(namespace_path:, template_id:, **overrides)
          group = authorized_find!(namespace_path: namespace_path)

          service = ::ComplianceManagement::Frameworks::CreateFromTemplateService.new(
            user: current_user,
            group: group,
            template_id: template_id.model_id,
            overrides: overrides
          ).execute

          if service.success?
            { framework: service.payload[:framework], errors: [] }
          else
            errors = [service.message]
            model_errors = service.payload.try(:full_messages).to_a

            { errors: (errors + model_errors).flatten }
          end
        end

        private

        def find_object(namespace_path:)
          ::Gitlab::Graphql::Loaders::FullPathModelLoader.new(::Namespace, namespace_path).find.sync
        end
      end
    end
  end
end
