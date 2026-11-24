# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      # rubocop:disable Graphql/AuthorizeTypes -- Parent node applies authorization
      class HealthStatusCountType < BaseObject
        graphql_name 'WorkItemWidgetHealthStatusCount'
        description 'Represents work item counts for the health status'

        field :health_status, ::Types::HealthStatusEnum, null: false,
          description: 'Health status of the work items.'

        field :count, GraphQL::Types::Int, null: false,
          description: 'Number of work items with the health status.'
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
