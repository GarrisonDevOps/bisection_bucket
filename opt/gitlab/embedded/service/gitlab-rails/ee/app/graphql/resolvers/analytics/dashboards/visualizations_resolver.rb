# frozen_string_literal: true

module Resolvers
  module Analytics
    module Dashboards
      class VisualizationsResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        calls_gitaly!
        authorizes_object!
        authorize :read_customizable_dashboards

        type [::Types::Analytics::Dashboards::VisualizationType], null: true

        argument :slug, GraphQL::Types::String, required: false, description: 'Slug of the visualization to return.'

        def resolve(slug: nil)
          visualizations = ::Analytics::Dashboards::Visualization.for(container: object, user: current_user)

          return visualizations if slug.blank?

          visualizations.select { |v| v.slug == slug }
        end
      end
    end
  end
end
