# frozen_string_literal: true

module Resolvers
  module Analytics
    module Dashboards
      class VisualizationResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        calls_gitaly!
        authorizes_object!
        authorize :read_customizable_dashboards

        type ::Types::Analytics::Dashboards::VisualizationType, null: true

        def resolve
          object.visualization
        end
      end
    end
  end
end
