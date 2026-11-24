# frozen_string_literal: true

module Resolvers
  module Analytics
    module Dashboards
      class DashboardsResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        calls_gitaly!
        authorizes_object!
        authorize :read_customizable_dashboards

        type [::Types::Analytics::Dashboards::DashboardType], null: true

        argument :slug, GraphQL::Types::String,
          required: false,
          description: 'Find by dashboard slug.'

        argument :category, ::Types::Analytics::Dashboards::CategoryEnum,
          required: false,
          description: 'Find by dashboard type.',
          default_value: ::Types::Analytics::Dashboards::CategoryEnum.values['ANALYTICS'].value

        def resolve(slug: nil, category: analytics_category_value)
          return object.product_analytics_dashboards(current_user) unless slug.present?

          category == analytics_category_value ? [object.product_analytics_dashboard(slug, current_user)] : []
        end

        private

        def analytics_category_value
          ::Types::Analytics::Dashboards::CategoryEnum.values['ANALYTICS'].value
        end
      end
    end
  end
end
