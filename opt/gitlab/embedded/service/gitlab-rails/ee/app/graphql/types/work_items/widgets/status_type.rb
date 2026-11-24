# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      # Disabling widget level authorization as it might be too granular
      # and we already authorize the parent work item
      # rubocop:disable Graphql/AuthorizeTypes -- reason above
      class StatusType < BaseObject
        graphql_name 'WorkItemWidgetStatus'
        description 'Represents status widget'

        authorize_granular_token skip_reason: :parent_authorizes

        implements ::Types::WorkItems::WidgetInterface

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :status, Types::WorkItems::StatusType,
          null: true,
          experiment: { milestone: '17.11' },
          scopes: [:api, :read_api, :ai_workflows],
          description: 'Status assigned to work item.',
          resolver: Resolvers::WorkItems::Statuses::StatusResolver
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
