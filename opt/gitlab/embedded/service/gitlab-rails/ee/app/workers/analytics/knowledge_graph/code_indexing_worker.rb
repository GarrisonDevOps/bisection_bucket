# frozen_string_literal: true

module Analytics
  module KnowledgeGraph
    class CodeIndexingWorker
      include ApplicationWorker

      data_consistency :delayed
      feature_category :knowledge_graph
      urgency :low
      deduplicate :until_executed
      idempotent!
      defer_on_database_health_signal :gitlab_main, [:p_knowledge_graph_code_indexing_tasks], 10.minutes

      concurrency_limit -> { 100 }

      def perform(project_id, ref, commit_sha)
        CodeIndexingTask.create_for_project(project_id, ref, commit_sha)
      end
    end
  end
end
