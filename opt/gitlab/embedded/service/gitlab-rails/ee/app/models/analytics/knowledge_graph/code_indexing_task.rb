# frozen_string_literal: true

module Analytics
  module KnowledgeGraph
    class CodeIndexingTask < ApplicationRecord
      include PartitionedTable

      RETENTION_DURATION = 1.day

      self.table_name = :p_knowledge_graph_code_indexing_tasks
      self.primary_key = :id

      partitioned_by :created_at, strategy: :daily, retain_for: RETENTION_DURATION

      belongs_to :project

      validates :ref, presence: true, length: { maximum: 255 }
      validates :commit_sha, presence: true, length: { maximum: 40 }
      validates :project_id, presence: true
      validates :traversal_path, presence: true, length: { maximum: 1024 }
      validates :repository_storage, length: { maximum: 255 }

      def self.create_for_project(project_id, ref, commit_sha)
        project = Project.find_by_id(project_id)
        return unless project&.knowledge_graph_indexing_enabled?

        create!(
          project_id: project_id,
          ref: ref,
          commit_sha: commit_sha,
          repository_storage: project.repository_storage,
          traversal_path: project.project_namespace.traversal_path(with_organization: true)
        )
      end
    end
  end
end
