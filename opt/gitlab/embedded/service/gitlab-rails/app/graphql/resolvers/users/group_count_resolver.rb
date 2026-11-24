# frozen_string_literal: true

module Resolvers
  module Users
    class GroupCountResolver < BaseResolver
      type GraphQL::Types::Int, null: true

      argument :organization_id, Types::GlobalIDType[::Organizations::Organization],
        required: false,
        prepare: ->(global_id, _ctx) { global_id&.model_id },
        experiment: { milestone: '19.6' },
        description: 'Global ID of the organization to scope the count to.'

      alias_method :user, :object

      def resolve(organization_id: nil)
        @organization_id = organization_id

        return if organization_id && organization.nil?
        return unless can_read_group_count?

        BatchLoader::GraphQL.for(user.id).batch(key: organization) do |user_ids, loader|
          results = UserGroupsCounter.new(user_ids, organization: organization).execute

          results.each do |user_id, count|
            loader.call(user_id, count)
          end
        end
      end

      def can_read_group_count?
        Ability.allowed?(current_user, :read_user_membership_counts, user) ||
          Ability.allowed?(current_user, :read_user_membership_counts, organization)
      end

      private

      def organization
        return unless @organization_id

        Gitlab::SafeRequestStore.fetch([:membership_counts_organization, @organization_id]) do
          ::Organizations::Organization.find_by_id(@organization_id)
        end
      end
      strong_memoize_attr :organization
    end
  end
end
