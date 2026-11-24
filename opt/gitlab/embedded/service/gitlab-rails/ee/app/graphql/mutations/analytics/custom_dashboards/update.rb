# frozen_string_literal: true

module Mutations
  module Analytics
    module CustomDashboards
      class Update < BaseMutation
        graphql_name 'UpdateCustomDashboard'
        description "Updates a custom dashboard."

        include Gitlab::Graphql::Authorize::AuthorizeResource
        include ::Analytics::CustomDashboards::ScopedToCurrentOrganization
        include WriteRateLimitable

        authorize :update_custom_dashboard
        authorize_granular_token permissions: :update_custom_dashboard, boundary: :instance, boundary_type: :instance

        argument :id,
          ::Types::GlobalIDType[::Analytics::CustomDashboards::Dashboard],
          required: true,
          description: "Global ID of the dashboard to update."

        argument :name, GraphQL::Types::String,
          required: false,
          deprecated: { reason: 'Use `config.title`', milestone: '19.6' },
          description: "Dashboard name."

        argument :description, GraphQL::Types::String,
          required: false,
          deprecated: { reason: 'Use `config.description`', milestone: '19.6' },
          description: "Dashboard description."

        # rubocop:disable Graphql/JSONType -- config is validated against ee/app/validators/json_schemas/analytics_dashboard.json
        argument :config, GraphQL::Types::JSON,
          required: false,
          description: 'Dashboard config, validated against the analytics dashboard JSON schema.'
        # rubocop:enable Graphql/JSONType

        field :dashboard, ::Types::Analytics::CustomDashboards::DashboardType,
          null: true,
          description: "Updated dashboard."

        field :errors, [GraphQL::Types::String],
          null: false,
          description: "Errors encountered during update."

        def resolve(id:, **attributes)
          dashboard = authorized_find!(id: id)

          params = attributes.compact

          return rate_limited_response if params.key?(:config) && write_throttled?

          response = ::Analytics::CustomDashboards::UpdateService
            .new(current_user: current_user, dashboard: dashboard, params: params)
            .execute

          if response.success?
            { dashboard: response.payload[:dashboard], errors: [] }
          else
            { dashboard: nil, errors: Array(response.message) }
          end
        end

        private

        def find_object(id:)
          find_current_organization_dashboard(id)
        end
      end
    end
  end
end
