# frozen_string_literal: true

module Resolvers
  module SecretsManagement
    class GroupSecretsCountResolver < BaseResolver
      include ::SecretsManagement::ResolverErrorHandling

      type GraphQL::Types::Int, null: true

      argument :group_path, GraphQL::Types::ID,
        required: true,
        description: 'Full path of the group.'

      def resolve(group_path:)
        group = Group.find_by_full_path(group_path)

        # secrets count is fetched by the group delete modal
        # some authorization access errors are due to feature flags
        # so we should return null in this case
        return unless Ability.allowed?(current_user, :read_secret, group)
        return unless group.secrets_manager&.active_after_refresh?

        ::SecretsManagement::GroupSecretsCountService.new(group, current_user).execute
      end
    end
  end
end
