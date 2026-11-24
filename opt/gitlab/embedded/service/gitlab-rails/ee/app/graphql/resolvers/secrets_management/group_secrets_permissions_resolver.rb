# frozen_string_literal: true

module Resolvers
  module SecretsManagement
    class GroupSecretsPermissionsResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource
      include ResolvesGroup
      include ::SecretsManagement::ResolverErrorHandling

      type [::Types::SecretsManagement::GroupSecretsPermissionType], null: true

      argument :group_path, GraphQL::Types::ID,
        required: true,
        description: 'Group the secrets permission belong to.'

      authorize :read_secrets_permission

      def resolve(group_path:)
        group = authorized_find!(group_path: group_path)

        result = ::SecretsManagement::GroupSecretsPermissions::ListService.new(
          group,
          current_user
        ).execute

        if result.success?
          result.payload[:secrets_permissions]
        else
          raise_resource_not_available_error!(result.message)
        end
      end

      private

      def find_object(group_path:)
        resolve_group(full_path: group_path)
      end
    end
  end
end
