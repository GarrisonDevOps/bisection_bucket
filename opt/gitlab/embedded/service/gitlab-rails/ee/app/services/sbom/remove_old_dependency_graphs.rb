# frozen_string_literal: true

module Sbom
  class RemoveOldDependencyGraphs
    include Gitlab::Utils::StrongMemoize

    BATCH_SIZE = 250
    RUNTIME_LIMIT = 4.minutes
    COMPLETED = :completed
    RUNTIME_LIMIT_REACHED = :runtime_limit_reached

    def self.execute(project)
      new(project).execute
    end

    def initialize(project)
      @project = project
      @cache_key_service = Sbom::LatestGraphTimestampCacheKey.new(project: project)
    end

    def execute
      start_runtime_limiter
      remove_old_dependency_graphs
    end

    private

    attr_reader :project, :runtime_limiter

    def start_runtime_limiter
      @runtime_limiter = Gitlab::Metrics::RuntimeLimiter.new(RUNTIME_LIMIT)
    end

    def remove_old_dependency_graphs
      status = COMPLETED
      deleted = 0

      old_graph_paths.each_batch(of: BATCH_SIZE) do |batch|
        deleted += batch.delete_all

        if runtime_limiter.over_time?
          status = RUNTIME_LIMIT_REACHED
          break
        end
      end

      ServiceResponse.success(payload: { job_status: status, deleted: deleted })
    end

    def old_graph_paths
      graph_paths.older_than(latest_timestamp)
    end

    def graph_paths
      Sbom::GraphPath.by_projects(project.id)
    end
    strong_memoize_attr :graph_paths

    def latest_timestamp
      read_timestamp_from_cache || graph_paths.maximum(:created_at)
    end

    def read_timestamp_from_cache
      @cache_key_service.retrieve
    end
  end
end
