# frozen_string_literal: true

module Mutations
  module Analytics
    module CustomDashboards
      class Delete < BaseMutation
        graphql_name 'DeleteCustomDashboard'
        description "Deletes a custom dashboard."

        include Gitlab::Graphql::Authorize::AuthorizeResource
        include ::Analytics::CustomDashboards::ScopedToCurrentOrganization

        authorize :delete_custom_dashboard
        authorize_granular_token permissions: :delete_custom_dashboard, boundary: :instance, boundary_type: :instance

        argument :id,
          ::Types::GlobalIDType[::Analytics::CustomDashboards::Dashboard],
          required: true,
          description: "Global ID of the dashboard to delete."

        field :dashboard, ::Types::Analytics::CustomDashboards::DashboardType,
          null: true,
          description: "Deleted dashboard."

        field :errors, [GraphQL::Types::String],
          null: false,
          description: "Errors encountered during deletion."

        def resolve(id:)
          dashboard = authorized_find!(id: id)

          response = ::Analytics::CustomDashboards::DeleteService
            .new(current_user: current_user, dashboard: dashboard)
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
