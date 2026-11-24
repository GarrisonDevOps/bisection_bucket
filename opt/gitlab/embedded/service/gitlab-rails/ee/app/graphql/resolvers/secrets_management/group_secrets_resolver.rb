# frozen_string_literal: true

module Resolvers
  module SecretsManagement
    class GroupSecretsResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource
      include ResolvesGroup
      include ::SecretsManagement::ResolverErrorHandling

      type [::Types::SecretsManagement::GroupSecretType], null: true
      extras [:lookahead]

      argument :group_path, GraphQL::Types::ID,
        required: true,
        description: 'Group the secrets belong to.'

      authorize :read_secret

      def resolve(lookahead:, group_path:)
        group = authorized_find!(group_path: group_path)

        result = ::SecretsManagement::GroupSecrets::ListService.new(
          group,
          current_user
        ).execute(include_rotation_info: include_rotation_info?(lookahead))

        if result.success?
          result.payload[:secrets]
        else
          raise_resource_not_available_error!(result.message)
        end
      end

      private

      def include_rotation_info?(lookahead)
        lookahead.selection(:nodes).selects?(:rotation_info) ||
          lookahead.selection(:edges).selection(:node).selects?(:rotation_info)
      end

      def find_object(group_path:)
        resolve_group(full_path: group_path)
      end
    end
  end
end
