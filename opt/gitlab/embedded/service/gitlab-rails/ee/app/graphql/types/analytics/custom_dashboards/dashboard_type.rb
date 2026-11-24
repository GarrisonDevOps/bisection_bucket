# frozen_string_literal: true

module Types
  module Analytics
    module CustomDashboards
      class DashboardType < BaseObject
        graphql_name 'CustomDashboard'

        authorize :read_custom_dashboard

        implements Types::Analytics::CustomDashboards::DashboardInterface

        description 'Customizable analytics dashboard'

        field :id,
          GraphQL::Types::ID,
          null: false,
          description: 'Global ID of the custom dashboard.'

        field :organization,
          Types::Organizations::OrganizationType,
          null: false,
          description: 'Organization that owns the dashboard.'

        field :namespace,
          Types::NamespaceType,
          null: true,
          description: 'Namespace scope of the dashboard, if any.'

        field :project,
          Types::ProjectType,
          null: true,
          description: 'Project scope of the dashboard, if any.'

        # rubocop:disable GraphQL/ExtractType -- Dashboard ownership tracking, not standard audit metadata
        field :created_by,
          Types::UserType,
          null: true,
          description: 'User who created the dashboard.'

        field :updated_by,
          Types::UserType,
          null: true,
          description: 'User who last updated the dashboard.'

        field :updated_at,
          Types::TimeType,
          null: false,
          description: 'Timestamp when the dashboard was last updated.'
        # rubocop:enable GraphQL/ExtractType

        field :lock_version,
          GraphQL::Types::Int,
          null: false,
          description: 'Version used for optimistic concurrency control.'
      end
    end
  end
end
