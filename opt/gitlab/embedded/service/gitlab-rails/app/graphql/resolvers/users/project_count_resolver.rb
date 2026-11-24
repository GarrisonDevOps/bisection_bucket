# frozen_string_literal: true

module Resolvers
  module Users
    class ProjectCountResolver < BaseResolver
      type GraphQL::Types::Int, null: true

      argument :organization_id, Types::GlobalIDType[::Organizations::Organization],
        required: false,
        prepare: ->(global_id, _ctx) { global_id&.model_id },
        experiment: { milestone: '19.6' },
        description: 'Global ID of the organization to scope the count to. ' \
          "Counts stop at #{::Users::ProjectsCounter::COUNT_LIMIT + 1}, which means more than #{::Users::ProjectsCounter::COUNT_LIMIT}."

      alias_method :user, :object

      def resolve(organization_id: nil)
        @organization_id = organization_id

        return if organization_id && organization.nil?
        return unless can_read_project_count?

        BatchLoader::GraphQL.for(user.id).batch(key: organization) do |user_ids, loader|
          counts = ::Users::ProjectsCounter.new(user_ids, organization: organization).execute

          user_ids.each do |id|
            loader.call(id, counts.fetch(id, 0))
          end
        end
      end

      def can_read_project_count?
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
