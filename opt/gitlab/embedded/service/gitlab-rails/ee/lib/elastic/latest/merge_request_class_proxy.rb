# frozen_string_literal: true

module Elastic
  module Latest
    class MergeRequestClassProxy < ApplicationClassProxy
      def elastic_search(query, options: {})
        query_hash = ::Search::Elastic::MergeRequestQueryBuilder.build(query: query, options: options)

        search(query_hash, options)
      end

      # rubocop: disable CodeReuse/ActiveRecord -- no ActiveRecord relation
      def preload_indexing_data(relation)
        relation.includes(:author, :assignees, :labels, target_project: [
          :project_feature, { namespace: %i[namespace_settings namespace_settings_with_ancestors_inherited_settings] }
        ])
      end
      # rubocop: enable CodeReuse/ActiveRecord
    end
  end
end
