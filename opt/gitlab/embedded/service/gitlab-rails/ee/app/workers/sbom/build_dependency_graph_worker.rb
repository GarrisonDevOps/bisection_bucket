# frozen_string_literal: true

module Sbom
  class BuildDependencyGraphWorker
    include ApplicationWorker

    deduplicate :until_executed, if_deduplicated: :reschedule_once
    idempotent!

    data_consistency :sticky
    worker_resource_boundary :cpu
    queue_namespace :sbom_graphs
    feature_category :dependency_management
    sidekiq_options retry: 2
    sidekiq_retry_in do |retry_count, exception, _jobhash|
      case exception
      when ActiveRecord::RecordInvalid, ActiveRecord::InvalidForeignKey
        # When this happens, it means that another job is removing Sbom::Occurrence
        # which happens only if there's a newer Ci::Pipeline that recently finished
        # In that case we can discard this job immediately
        :discard
      else
        # Retry after a minute, two, three or fail
        retry_count * 60
      end
    end

    defer_on_database_health_signal :gitlab_sec, [:sbom_graph_paths], 1.minute

    def perform(project_id)
      project = Project.find_by_id(project_id)
      return unless project

      Sbom::BuildDependencyGraph.execute(project)
    end
  end
end
