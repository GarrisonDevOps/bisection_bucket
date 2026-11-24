# frozen_string_literal: true

module Types
  module Analytics
    module CustomDashboards
      module DashboardInterface
        include Types::BaseInterface

        graphql_name 'CustomDashboardInterface'
        orphan_types Types::Analytics::CustomDashboards::DashboardType,
          Types::Analytics::CustomDashboards::SystemDashboardType

        field :id, GraphQL::Types::ID, null: false,
          description: 'Global ID of the dashboard.'

        field :name, GraphQL::Types::String, null: false,
          description: 'Display name of the dashboard.'

        field :description, GraphQL::Types::String, null: true,
          description: 'Optional summary or purpose of the dashboard.'

        # rubocop:disable Graphql/JSONType -- JSON schema validation enforces structure
        field :config, GraphQL::Types::JSON, null: false,
          description: 'Dashboard layout and widget configuration.'
        # rubocop:enable Graphql/JSONType

        field :created_at, Types::TimeType, null: true,
          description: 'Timestamp when the dashboard was created.'

        field :system, GraphQL::Types::Boolean, null: false, method: :system?,
          description: 'Whether the dashboard is a built-in GitLab dashboard.'

        field :slug, GraphQL::Types::String, null: true,
          description: 'Dashboard url slug.'

        def self.resolve_type(object, _context)
          if object.is_a?(::Analytics::CustomDashboards::SystemDashboard)
            Types::Analytics::CustomDashboards::SystemDashboardType
          else
            Types::Analytics::CustomDashboards::DashboardType
          end
        end
      end
    end
  end
end
