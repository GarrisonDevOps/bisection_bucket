# frozen_string_literal: true

module Ci
  class ExecuteBuildHooksWorker
    include ApplicationWorker

    data_consistency :delayed

    feature_category :continuous_integration
    urgency :low
    # GitLab.com runs this on low-urgency-ci-pipeline. The 25% low-urgency default sits below the
    # worker's peak there; 45% clears it. 20% of that caps one top-level group at 9% of the shard.
    max_concurrency_limit_percentage 0.45
    concurrency_limit_scope(:root_namespace, max_percentage: 0.2,
      enabled: -> { Feature.enabled?(:ci_pipeline_execution_concurrency_limit_scope_wave_three, :instance) })

    idempotent!

    def perform(project_id, build_id, build_state = nil)
      project = Project.find_by_id(project_id)
      return unless project
      return unless project.has_active_hooks?(:job_hooks) || project.has_active_integrations?(:job_hooks)

      cache_enabled = Feature.enabled?(:ci_build_hook_commit_cache, Project.actor_from_id(project_id))
      build_data = resolve_build_data(project, build_id, build_state, cache_enabled)
      return unless build_data

      project.execute_hooks(build_data, :job_hooks) if project.has_active_hooks?(:job_hooks)
      project.execute_integrations(build_data, :job_hooks) if project.has_active_integrations?(:job_hooks)

      log_extra_metadata_on_done(:build_status, build_data[:build_status])
    end

    private

    def resolve_build_data(project, build_id, build_state, cache_enabled)
      return if build_id.is_a?(Hash)

      build = Ci::Build.find_by_id(build_id)
      return unless build

      ActiveRecord::Associations::Preloader.new(records: [build], associations: { runner: :tags }).call

      data = if cache_enabled && build.project_id == project.id
               git_commit = Gitlab::Ci::BuildHookCommitCache.new(project, build.sha).fetch { Commit.lazy(project, build.sha).itself }
               Gitlab::DataBuilder::Build.build(build, git_commit: git_commit)
             else
               Gitlab::DataBuilder::Build.build(build)
             end

      data
        .with_indifferent_access
        .merge(pinned_attributes(build_state))
    end

    def pinned_attributes(build_state)
      attributes = build_state.to_h.with_indifferent_access

      %w[build_started_at build_finished_at].each do |field|
        next unless attributes.key?(field)

        attributes["#{field}_iso"] = attributes[field]&.to_time&.utc&.iso8601
      end

      attributes
    end
  end
end
