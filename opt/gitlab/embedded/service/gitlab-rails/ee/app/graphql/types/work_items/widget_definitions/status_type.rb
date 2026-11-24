# frozen_string_literal: true

module Types
  module WorkItems
    module WidgetDefinitions
      # rubocop:disable Graphql/AuthorizeTypes -- Authorization too granular, parent type is authorized
      class StatusType < BaseObject
        graphql_name 'WorkItemWidgetDefinitionStatus'
        description 'Represents a Status widget definition'

        authorize_granular_token skip_reason: :parent_authorizes

        include ::Resolvers::WorkItems::Widgets::StatusLifecycle

        implements ::Types::WorkItems::WidgetDefinitionInterface

        field :allowed_statuses, [::Types::WorkItems::StatusType],
          null: true, experiment: { milestone: '17.8' },
          description: 'Allowed statuses for the work item type.',
          resolver: ::Resolvers::WorkItems::Widgets::AllowedStatusesResolver

        # rubocop: disable GraphQL/ExtractType -- no value for now
        field :default_open_status, ::Types::WorkItems::StatusType,
          null: true, experiment: { milestone: '18.0' },
          description: 'Default status for the `Open` state for given work item type.'

        field :default_closed_status, ::Types::WorkItems::StatusType,
          null: true, experiment: { milestone: '18.0' },
          description: 'Default status for the `Closed` state for given work item type.'
        # rubocop: enable GraphQL/ExtractType

        def default_open_status
          status_lifecycle&.default_open_status
        end

        def default_closed_status
          status_lifecycle&.default_closed_status
        end
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
