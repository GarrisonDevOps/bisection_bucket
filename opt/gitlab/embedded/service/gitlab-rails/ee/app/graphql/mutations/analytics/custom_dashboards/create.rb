# frozen_string_literal: true

module Mutations
  module Analytics
    module CustomDashboards
      class Create < BaseMutation
        graphql_name 'CreateCustomDashboard'
        description "Creates a custom dashboard in an organization."

        include Gitlab::Graphql::Authorize::AuthorizeResource
        include ::Analytics::CustomDashboards::ScopedToCurrentOrganization
        include WriteRateLimitable

        authorize :create_custom_dashboard
        authorize_granular_token permissions: :create_custom_dashboard, boundary: :instance, boundary_type: :instance

        argument :organization_id,
          ::Types::GlobalIDType[::Organizations::Organization],
          required: false,
          description: "Organization the dashboard belongs to. Must be the current organization, " \
            "which is used when not provided."

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
          required: true,
          description: 'Dashboard config, validated against the analytics dashboard JSON schema.'
        # rubocop:enable Graphql/JSONType

        argument :namespace_id, ::Types::GlobalIDType[::Namespace],
          required: false,
          description: "Namespace to scope the dashboard to."

        field :dashboard, ::Types::Analytics::CustomDashboards::DashboardType,
          null: true,
          description: "Newly created dashboard."

        field :errors, [GraphQL::Types::String],
          null: false,
          description: "Errors encountered during creation."

        def resolve(organization_id: nil, namespace_id: nil, **attributes)
          organization = find_current_organization(organization_id)

          raise_resource_not_available_error! 'Organization not found' unless organization

          authorize!(organization)

          return rate_limited_response if write_throttled?

          params = attributes.merge(namespace_id: parse_gid(namespace_id)).compact

          response = ::Analytics::CustomDashboards::CreateService
            .new(current_user: current_user, organization: organization, params: params)
            .execute

          if response.success?
            { dashboard: response.payload[:dashboard], errors: [] }
          else
            { dashboard: nil, errors: Array(response.message) }
          end
        end

        private

        def parse_gid(gid)
          return unless gid

          GlobalID::Locator.locate(gid)&.id
        rescue ActiveRecord::RecordNotFound
          nil
        end
      end
    end
  end
end
