# frozen_string_literal: true

module Resolvers
  module Analytics
    module CustomDashboards
      class SystemDashboardResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        authorize :read_system_dashboard

        type Types::Analytics::CustomDashboards::SystemDashboardType, null: true

        argument :slug,
          GraphQL::Types::String,
          required: true,
          description: 'Slug of the system dashboard (e.g. "duo_and_sdlc_trends").'

        def resolve(slug:)
          dashboard = ::Analytics::CustomDashboards::SystemDashboardsLoader.find_by_slug(slug)

          return unless dashboard

          authorize!(dashboard)

          dashboard
        end
      end
    end
  end
end
