# frozen_string_literal: true

module Sbom
  class RemoveOldDependencyGraphsWorker
    include ApplicationWorker
    include Gitlab::Utils::StrongMemoize

    deduplicate :until_executing
    idempotent!

    data_consistency :sticky
    worker_resource_boundary :cpu
    queue_namespace :sbom_graphs
    feature_category :dependency_management

    defer_on_database_health_signal :gitlab_sec, [:sbom_graph_paths], 1.minute

    RESCHEDULE_TIMEOUT = 2.minutes

    def perform(project_id)
      project = Project.find_by_id(project_id)

      return unless project

      result = Sbom::RemoveOldDependencyGraphs.execute(project)

      reschedule(project.id) if result.payload[:job_status] == Sbom::RemoveOldDependencyGraphs::RUNTIME_LIMIT_REACHED

      log_extra_metadata_on_done(:result, result.payload)
    end

    private

    def reschedule(project_id)
      self.class.perform_in(RESCHEDULE_TIMEOUT, project_id)
    end
  end
end
