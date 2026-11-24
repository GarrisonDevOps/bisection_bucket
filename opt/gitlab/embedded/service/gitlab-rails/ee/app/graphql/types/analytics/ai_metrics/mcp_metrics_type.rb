# frozen_string_literal: true

module Types
  module Analytics
    module AiMetrics
      # rubocop: disable Graphql/AuthorizeTypes -- authorized by parent type
      class McpMetricsType < BaseObject
        graphql_name 'mcpMetrics'
        description "Model Context Protocol metrics. Requires ClickHouse. Premium and Ultimate only."

        include ::Analytics::AiEventFields

        expose_event_fields_for(:mcp)
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
