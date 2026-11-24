# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      # rubocop:disable Graphql/AuthorizeTypes -- Disabling widget level authorization
      class DecisionLogType < BaseObject
        graphql_name 'WorkItemWidgetDecisionLog'
        description 'Represents a decision log widget'

        authorize_granular_token skip_reason: :parent_authorizes

        implements ::Types::WorkItems::WidgetInterface

        field :decisions,
          ::Types::WorkItems::DecisionType.connection_type,
          null: true,
          experiment: { milestone: '19.4' },
          description: 'Decisions recorded on the work item. Can be requested once per query; ' \
            'use `states` to fetch several states in one call.' do
          argument :states, [::Types::WorkItems::DecisionStateEnum],
            required: false,
            validates: { length: { maximum: ::Types::WorkItems::DecisionStateEnum.values.size } },
            description: 'Filter decisions by one or more states. Omit to return all states.'

          # Cheap to resolve today (preloaded), but deliberately capped to
          # one work item per query: all current consumers are single-item,
          # and relaxing the cap later is non-breaking while re-adding it
          # after GA would not be
          extension ::Gitlab::Graphql::Limit::FieldCallCount, limit: 1
        end

        def decisions(states: nil)
          decisions = object.decisions
          return decisions if states.blank?

          decisions.with_states(states)
        end
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
