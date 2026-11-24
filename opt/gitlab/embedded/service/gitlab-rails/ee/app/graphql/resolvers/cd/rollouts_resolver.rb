# frozen_string_literal: true

module Resolvers
  module Cd
    class RolloutsResolver < BaseResolver
      include LooksAhead

      max_page_size 20

      type ::Types::Cd::RolloutType.connection_type, null: true

      argument :statuses, [::Types::Cd::RolloutStatusEnum],
        description: 'Filter rollouts by status.',
        required: false

      alias_method :application, :object

      argument :search, GraphQL::Types::String,
        required: false,
        description: 'Search rollouts by ID (IID).'

      def resolve_with_lookahead(search: nil, statuses: nil, **)
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        rollouts = application.rollouts
        rollouts = rollouts.search_by_iid(search) if search.present?
        rollouts = rollouts.for_statuses(statuses) if statuses.present?

        apply_lookahead(rollouts)
      end

      private

      def preloads
        {
          rollout_environments: [:rollout_environments],
          rollout_transitions: [:rollout_transitions]
        }
      end
    end
  end
end
