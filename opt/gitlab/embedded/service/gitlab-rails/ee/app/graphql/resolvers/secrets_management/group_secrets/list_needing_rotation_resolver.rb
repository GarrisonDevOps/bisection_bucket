# frozen_string_literal: true

module Resolvers
  module SecretsManagement
    module GroupSecrets
      class ListNeedingRotationResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource
        include ResolvesGroup
        include ::SecretsManagement::ResolverErrorHandling

        type [::Types::SecretsManagement::GroupSecretType], null: true

        argument :group_path, GraphQL::Types::ID,
          required: true,
          description: 'Group the secrets belong to.'

        authorize :read_secret

        def resolve(group_path:)
          group = authorized_find!(group_path: group_path)

          result = ::SecretsManagement::GroupSecrets::ListNeedingRotationService.new(
            group,
            current_user
          ).execute

          if result.success?
            result.payload[:secrets]
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
end
