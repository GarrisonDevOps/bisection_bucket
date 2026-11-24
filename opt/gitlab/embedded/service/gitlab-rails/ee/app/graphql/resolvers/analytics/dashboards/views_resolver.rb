# frozen_string_literal: true

module Resolvers
  module Analytics
    module Dashboards
      class ViewsResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        calls_gitaly!
        authorizes_object!
        authorize :read_customizable_dashboards

        type [::Types::Analytics::Dashboards::ViewType], null: false

        def resolve
          object.views
        end
      end
    end
  end
end
