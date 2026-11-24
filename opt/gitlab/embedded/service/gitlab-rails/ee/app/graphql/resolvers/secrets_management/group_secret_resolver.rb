# frozen_string_literal: true

module Resolvers
  module SecretsManagement
    class GroupSecretResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource
      include ResolvesGroup
      include ::SecretsManagement::ResolverErrorHandling

      type ::Types::SecretsManagement::GroupSecretType, null: true
      extras [:lookahead]

      argument :group_path, GraphQL::Types::ID,
        required: true,
        description: 'Group the secret belongs to.'

      argument :name, GraphQL::Types::String,
        required: true,
        description: 'Name of the group secret to view.'

      authorize :read_secret

      def resolve(lookahead:, group_path:, name:)
        group = authorized_find!(group_path: group_path)

        result = ::SecretsManagement::GroupSecrets::ReadMetadataService.new(group, current_user)
          .execute(name, include_rotation_info: lookahead.selects?(:rotation_info))

        if result.success?
          result.payload[:secret]
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
