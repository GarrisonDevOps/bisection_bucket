# frozen_string_literal: true

module Elastic
  module Latest
    class ProjectClassProxy < ApplicationClassProxy
      extend ::Gitlab::Utils::Override

      def elastic_search(query, options: {})
        query_hash = ::Search::Elastic::ProjectQueryBuilder.build(query: query, options: options)

        search(query_hash, options)
      end

      override :routing_options
      def routing_options(options)
        group = Group.find_by_id(options[:group_id])

        return {} unless group

        root_namespace_id = group.root_ancestor.id

        { routing: "n_#{root_namespace_id}" }
      end

      def preload_indexing_data(relation)
        relation.preload_for_indexing
      end
    end
  end
end
