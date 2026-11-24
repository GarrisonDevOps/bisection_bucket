# frozen_string_literal: true

module Types
  module Ai
    # rubocop: disable Graphql/AuthorizeTypes, GraphQL/GraphqlName -- the parent field authorizes; graphql-ruby names the connection
    class FlowTriggerConnectionType < Types::CountableConnectionType
      field_class ::Types::BaseField

      field :run_stats, Types::Ai::FlowTrigger::RunStatsType,
        null: true,
        experiment: { milestone: '19.6' },
        description: 'Statistics of the runs created in the last 30 days by all flow triggers in the collection, ' \
          'not only the current page.'

      def run_stats
        workflows = ::Gitlab::Graphql::Loaders::Ai::FlowTriggerRunSummaryLoader
          .visible_workflows(object.parent, object.items.to_a, context[:current_user])
          .created_after_in_project(object.parent, ::Ai::FlowTrigger::RUN_STATS_WINDOW.ago)

        workflows.run_stats.merge(daily_volume: workflows.daily_runs)
      end
    end
    # rubocop: enable Graphql/AuthorizeTypes, GraphQL/GraphqlName
  end
end
