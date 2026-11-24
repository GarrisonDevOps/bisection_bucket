# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      # rubocop:disable Graphql/AuthorizeTypes
      class HealthStatusType < BaseObject
        graphql_name 'WorkItemWidgetHealthStatus'
        description 'Represents a health status widget'

        authorize_granular_token skip_reason: :parent_authorizes

        implements ::Types::WorkItems::WidgetInterface

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :health_status,
          ::Types::HealthStatusEnum,
          null: true, scopes: [:api, :read_api, :ai_workflows],
          description: 'Health status of the work item.'

        field :rolled_up_health_status, [::Types::WorkItems::Widgets::HealthStatusCountType],
          null: true,
          description: 'Rolled up health status of the work item.',
          experiment: { milestone: '17.3' }
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
