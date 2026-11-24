# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      # Disabling widget level authorization as it might be too granular
      # and we already authorize the parent work item
      # rubocop:disable Graphql/AuthorizeTypes
      class IterationType < BaseObject
        graphql_name 'WorkItemWidgetIteration'
        description 'Represents an iteration widget'

        authorize_granular_token skip_reason: :parent_authorizes

        implements ::Types::WorkItems::WidgetInterface

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :iteration,
          ::Types::IterationType,
          null: true, scopes: [:api, :read_api, :ai_workflows],
          description: 'Iteration of the work item.'
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
