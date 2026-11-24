# frozen_string_literal: true

module Types
  module Analytics
    module Dashboards
      class DashboardType < BaseObject
        graphql_name 'CustomizableDashboard'
        description 'Represents a customizable dashboard.'
        authorize :read_customizable_dashboards

        field :title,
          type: GraphQL::Types::String,
          null: true,
          description: 'Title of the dashboard.'

        field :category,
          type: Types::Analytics::Dashboards::CategoryEnum,
          null: false,
          description: 'Category of dashboard.'

        field :slug,
          type: GraphQL::Types::String,
          null: false,
          description: 'Slug of the dashboard.'

        field :description,
          type: GraphQL::Types::String,
          null: true,
          description: 'Description of the dashboard.'

        field :status,
          type: GraphQL::Types::String,
          null: true,
          description: 'Status of the dashboard.',
          experiment: { milestone: '17.0' }

        field :grid_height,
          type: Types::Analytics::Dashboards::GridHeightEnum,
          null: true,
          description: 'Grid cell height of the dashboard.',
          experiment: { milestone: '18.9' }

        field :panels,
          type: Types::Analytics::Dashboards::PanelType.connection_type,
          null: true,
          description: 'Panels shown on the dashboard.'

        field :user_defined,
          type: GraphQL::Types::Boolean,
          null: false,
          description: 'Indicates whether the dashboard is user-defined or provided by GitLab.'

        field :configuration_project,
          type: Types::ProjectType,
          method: :config_project,
          null: true,
          description: 'Project which contains the dashboard definition.'

        field :errors,
          type: [GraphQL::Types::String],
          null: true,
          description: 'Errors on yaml definition.'

        field :filters,
          type: GraphQL::Types::JSON,
          null: true,
          description: 'Dashboard global filters.'
      end
    end
  end
end
