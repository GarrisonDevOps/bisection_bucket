# frozen_string_literal: true

module Mutations
  module Security
    module Categories
      class Update < BaseMutation
        graphql_name 'SecurityCategoryUpdate'

        authorize :admin_security_attributes
        authorize_granular_token permissions: :update_security_category,
          boundary_argument: :namespace_id, boundary_type: :group

        argument :description, GraphQL::Types::String,
          required: false,
          description: 'Description of the security category.'

        argument :id, ::Types::GlobalIDType[::Security::Category],
          required: true,
          description: 'Global ID of the security category.'

        argument :name, GraphQL::Types::String,
          required: false,
          description: 'Name of the security category.'

        argument :namespace_id, ::Types::GlobalIDType[::Namespace],
          required: true,
          description: 'Global ID of the category namespace.'

        field :security_category, Types::Security::CategoryType,
          null: true,
          description: 'Updated security category.'

        def resolve(id:, namespace_id:, **params)
          namespace = authorized_find!(id: namespace_id)

          category_result = ::Security::Categories::FindOrCreateService.new(
            category_id: GitlabSchema.parse_gid(id, expected_type: ::Security::Category).model_id,
            namespace: namespace,
            current_user: current_user
          ).execute
          return { errors: category_result.errors } if category_result.error?

          category = category_result.payload[:category]
          raise_resource_not_available_error! unless category

          result = ::Security::Categories::UpdateService.new(
            category: category, current_user: current_user, params: params
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
