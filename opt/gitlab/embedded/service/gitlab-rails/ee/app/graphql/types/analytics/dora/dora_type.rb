# frozen_string_literal: true

module Types
  module Analytics
    module Dora
      class DoraType < BaseObject
        graphql_name 'Dora'
        description 'All information related to DORA metrics.'

        include Gitlab::Graphql::Authorize::AuthorizeResource

        authorizes_object!
        authorize :read_dora4_analytics

        field :metrics, [DoraMetricType],
          null: true,
          resolver: ::Resolvers::Analytics::Dora::DoraMetricsResolver,
          description: 'DORA metrics for the current group or project.'
      end
    end
  end
end
