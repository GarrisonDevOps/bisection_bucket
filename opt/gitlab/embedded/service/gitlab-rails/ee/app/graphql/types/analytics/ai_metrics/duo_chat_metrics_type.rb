# frozen_string_literal: true

module Types
  module Analytics
    module AiMetrics
      # rubocop: disable Graphql/AuthorizeTypes -- authorized by parent type
      class DuoChatMetricsType < BaseObject
        graphql_name 'duoChatMetrics'
        description "Requires ClickHouse. Premium and Ultimate only."

        include ::Analytics::AiEventFields

        expose_event_fields_for(:chat)
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
