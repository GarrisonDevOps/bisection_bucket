# frozen_string_literal: true

module Search
  module Zoekt
    class Router
      def self.fetch_indices_for_indexing(project_id, root_namespace_id:)
        replicas = Replica.for_namespace(root_namespace_id)
        index_ids = []

        replicas.joins(:indices).distinct.find_each do |replica|
          repos = replica.fetch_repositories_with_project_identifier(project_id)

          if repos.present?
            repos.find_each do |repo|
              index_ids << repo.zoekt_index.id
            end
          else
            index_ids << replica.indices.max_by(&:free_storage_bytes).id
          end
        end

        Index.where(id: index_ids)
      end

      def self.fetch_nodes_for_indexing(project_id, root_namespace_id:, node_ids: [])
        return Node.for_search.where(id: node_ids) unless node_ids.compact.empty?

        index_ids = fetch_indices_for_indexing(project_id, root_namespace_id: root_namespace_id).select(:id)
        Node.for_search.joins(:indices).where(indices: { id: index_ids })
      end
    end
  end
end
