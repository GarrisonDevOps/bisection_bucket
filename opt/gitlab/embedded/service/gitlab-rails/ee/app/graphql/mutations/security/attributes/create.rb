# frozen_string_literal: true

module Mutations
  module Security
    module Attributes
      class Create < BaseMutation
        graphql_name 'SecurityAttributeCreate'

        authorize :admin_security_attributes
        authorize_granular_token permissions: :create_security_attribute,
          boundary_argument: :namespace_id, boundary_type: :group

        argument :attributes, [Types::Security::AttributeInputType],
          required: true,
          description: 'Attributes to create.'

        argument :category_id, ::Types::GlobalIDType[::Security::Category],
          required: true,
          description: 'Global ID of the security category.'

        argument :namespace_id, ::Types::GlobalIDType[::Namespace],
          required: true,
          description: 'Global ID of the namespace.'

        field :security_attributes, [Types::Security::AttributeType],
          null: true,
          description: 'Created security attributes.'

        def resolve(attributes:, category_id:, namespace_id: nil)
          namespace = authorized_find!(id: namespace_id)

          category_result = ::Security::Categories::FindOrCreateService.new(
            category_id: GitlabSchema.parse_gid(category_id, expected_type: ::Security::Category).model_id,
            namespace: namespace,
            current_user: current_user
          ).execute
          category = category_result.payload[:category]
          raise_resource_not_available_error! unless category
          return { security_attributes: nil, errors: category_result.errors } if category_result.error?

          validate_category_attribute_limit(category, attributes.length)

          result = ::Security::Attributes::CreateService.new(
            category: category,
            namespace: namespace,
            current_user: current_user,
            params: { attributes: attributes }
          ).execute

          {
            security_attributes: result.success? ? result.payload[:attributes] : nil,
            errors: result.errors
          }
        end

        private

        def validate_category_attribute_limit(category, new_attributes_count)
          return unless category

          current_count = category.not_deleted_security_attributes.count
          expected_attribute_count = current_count + new_attributes_count
          return unless expected_attribute_count > ::Security::Category::MAX_ATTRIBUTES

          raise Gitlab::Graphql::Errors::ArgumentError,
            "Category cannot have more than #{::Security::Category::MAX_ATTRIBUTES} attributes."
        end
      end
    end
  end
end
