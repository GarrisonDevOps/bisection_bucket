# frozen_string_literal: true

module Resolvers
  module Analytics
    module CustomDashboards
      class DashboardsResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource
        include ::Analytics::CustomDashboards::ScopedToCurrentOrganization

        authorize :read_system_dashboard

        type Types::Analytics::CustomDashboards::DashboardInterface.connection_type, null: true

        argument :organization_id,
          ::Types::GlobalIDType[::Organizations::Organization],
          required: false,
          description: 'Organization ID to filter dashboards. Must be the current organization, ' \
            'which is used when not provided.'

        argument :namespace_id,
          ::Types::GlobalIDType[::Namespace],
          required: false,
          description: 'Filter by namespace.'

        argument :created_by_id,
          ::Types::GlobalIDType[::User],
          required: false,
          description: 'Filter by dashboard creator.'

        argument :search,
          GraphQL::Types::String,
          required: false,
          description: 'Filter dashboards by name.'

        argument :scope,
          Types::Analytics::CustomDashboards::DashboardScopeEnum,
          required: false,
          default_value: :all,
          description: 'Filter dashboards by scope.'

        def resolve(organization_id: nil, **filter_args)
          organization = find_current_organization(organization_id)

          raise_resource_not_available_error! 'Organization not found' unless organization

          # Only an explicit ID is rejected for non-members; the default path still
          # returns an empty list, which the Explore page renders as its empty state.
          authorize!(organization) if organization_id

          ::Analytics::CustomDashboards::DashboardsLoaderService.new(
            current_user,
            organization: organization,
            params: build_params(filter_args)
          ).execute
        end

        private

        def build_params(filter_args)
          {
            namespace_id: parse_gid(filter_args[:namespace_id]),
            created_by_id: parse_gid(filter_args[:created_by_id]),
            search: filter_args[:search],
            scope: filter_args[:scope]&.to_sym
          }.compact
        end

        def parse_gid(gid)
          return unless gid

          GitlabSchema.parse_gid(gid).model_id
        end
      end
    end
  end
end
