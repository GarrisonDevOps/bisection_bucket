# frozen_string_literal: true

module Mutations
  module Security
    module Categories
      class Create < BaseMutation
        graphql_name 'SecurityCategoryCreate'

        authorize :admin_security_attributes
        authorize_granular_token permissions: :create_security_category,
          boundary_argument: :namespace_id, boundary: :root_ancestor, boundary_type: :group

        argument :description, GraphQL::Types::String,
          required: false,
          description: 'Description of the security category.'
        argument :multiple_selection, GraphQL::Types::Boolean,
          required: false,
          description: 'Whether multiple attributes can be selected.'
        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Name of the security category.'
        argument :namespace_id, ::Types::GlobalIDType[::Namespace],
          required: true,
          description: 'Global ID of the category namespace.'

        field :security_category, Types::Security::CategoryType,
          null: true,
          description: 'Created security category.'

        def resolve(namespace_id:, **params)
          namespace = authorized_find!(id: namespace_id)

          result = ::Security::Categories::CreateService.new(
            namespace: namespace,
            current_user: current_user,
            params: params
          ).execute

          {
            security_category: result.success? ? result.payload[:category] : nil,
            errors: result.errors
          }
        end
      end
    end
  end
end
