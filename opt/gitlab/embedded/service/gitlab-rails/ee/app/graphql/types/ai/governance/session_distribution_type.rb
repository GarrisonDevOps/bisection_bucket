# frozen_string_literal: true

module Types
  module Ai
    module Governance
      # Reachable only through fields that already authorize against the
      # group or project, so no object-level authorization is needed here.
      class SessionDistributionType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'AiGovernanceSessionDistribution'
        description 'AI sessions and developers in the timeframe, split by agent or flow type.'

        authorize_granular_token skip_reason: :parent_authorizes

        field :slices, [Types::Ai::Governance::SessionDistributionSliceType], null: false,
          description: 'Slices ordered by developers, then sessions, then name. ' \
            "Returns the top #{::Ai::Governance::MetricsService::SESSION_DISTRIBUTION_LIMIT}. " \
            "Missing names are reported as `#{::Ai::Governance::Session::DISTRIBUTION_FALLBACK_NAME}`."
        # rubocop:disable GraphQL/ExtractType -- flat totals shape agreed with the dashboard card
        field :total_developers, GraphQL::Types::Int, null: false,
          description: 'Number of distinct developers with sessions in the timeframe, across all slices.'
        field :total_sessions, GraphQL::Types::Int, null: false,
          description: 'Number of sessions in the timeframe, across all slices.'
        # rubocop:enable GraphQL/ExtractType
      end
    end
  end
end
