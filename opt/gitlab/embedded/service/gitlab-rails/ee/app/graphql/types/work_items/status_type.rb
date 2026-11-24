# frozen_string_literal: true

module Types
  module WorkItems
    # rubocop:disable Graphql/AuthorizeTypes -- parent work item type already authorizes
    class StatusType < BaseObject
      graphql_name 'WorkItemStatus'

      # This type skips granular token auth: every field returning it must require
      # read_work_item itself. Reached via:
      # 1. WorkItem -> WorkItemWidgetStatus: parent WorkItem gates read_work_item.
      # 2. Query.workItemAllowedStatuses: field-level directive is the only gate.
      # 3. Group.statuses: GroupType gates read_group only, so that field adds its own
      #    read_work_item directive.
      authorize_granular_token skip_reason: :parent_authorizes
      description 'Represents status'

      def self.authorization_scopes
        super + [:ai_workflows]
      end

      field :id, Types::GlobalIDType,
        null: true,
        scopes: [:api, :read_api, :ai_workflows],
        experiment: { milestone: '17.11' },
        description: 'ID of the status.'

      field :name, GraphQL::Types::String,
        null: true,
        scopes: [:api, :read_api, :ai_workflows],
        experiment: { milestone: '17.11' },
        description: 'Name of the status.'

      field :icon_name, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '17.11' },
        description: 'Icon name of the status.'

      field :color, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '17.11' },
        description: 'Color of the status.'

      field :position, GraphQL::Types::Int,
        null: true,
        experiment: { milestone: '17.11' },
        description: 'Position of the status within its category.'

      field :description, GraphQL::Types::String,
        null: true,
        experiment: { milestone: '18.1' },
        description: 'Description of the status.'

      field :category, Types::WorkItems::StatusCategoryEnum,
        null: true,
        experiment: { milestone: '18.1' },
        description: 'Category of the status.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
