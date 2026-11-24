# frozen_string_literal: true

module Types
  module Ai
    module Governance
      # Reachable only through fields that already authorize against the
      # group or project, so no object-level authorization is needed here.
      class KpiTrendPointType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'AiGovernanceKpiTrendPoint'
        description 'Single bucket of an AI governance KPI trend series.'

        authorize_granular_token skip_reason: :parent_authorizes

        field :bucket_start, Types::TimeType, null: false,
          description: 'Timestamp of the start of the bucket.'
        field :count, GraphQL::Types::Int, null: false,
          description: 'Count of items in the bucket.'
      end
    end
  end
end
