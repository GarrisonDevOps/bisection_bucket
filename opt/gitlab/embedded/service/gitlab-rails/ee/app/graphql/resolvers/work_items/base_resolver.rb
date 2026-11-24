# frozen_string_literal: true

module Resolvers
  module WorkItems
    class BaseResolver < Resolvers::BaseResolver # rubocop:disable Graphql/ResolverType -- Child class defines the type
      include Gitlab::Graphql::Authorize::AuthorizeResource

      def work_item_status_licensed_feature_available?
        root_ancestor&.licensed_feature_available?(:work_item_status)
      end
    end
  end
end
