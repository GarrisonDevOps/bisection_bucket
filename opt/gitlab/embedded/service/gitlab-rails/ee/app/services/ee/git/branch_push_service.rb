# frozen_string_literal: true

module EE
  module Git
    module BranchPushService
      extend ::Gitlab::Utils::Override

      REPOSITORY_XRAY_SCAN_PERIOD = 1.day

      override :execute
      def execute
        enqueue_elasticsearch_indexing
        enqueue_zoekt_indexing
        enqueue_knowledge_graph_code_indexing
        enqueue_code_embedding_indexing
        enqueue_update_external_pull_requests
        enqueue_repository_xray
        enqueue_sync_pipeline_execution_policy_metadata
        enqueue_publish_ai_catalog_skills
        enqueue_dap_factory_sync

        super
      end

      private

      def enqueue_dap_factory_sync
        return unless default_branch?
        return unless ::Gitlab::Ai::SoftwareFactory.enabled?(project)

        ::Ai::DapFactory::SyncWorker.perform_async(project.id, current_user.id, oldrev, newrev, ref)
      end

      # No skills-specific opt-in, because the first SKILL.md a project ever commits has to work.
      def enqueue_publish_ai_catalog_skills
        return unless default_branch?
        return unless ::Feature.enabled?(:ai_catalog_skills, project)
        return unless ::Ai::Catalog.available_for_project?(project)

        ::Ai::Catalog::Skills::PublishWorker.perform_async(project.id, oldrev, newrev, ref)
      end

      def enqueue_sync_pipeline_execution_policy_metadata
        return unless ::Security::PolicyAvailability.any_available?(project)

        return if ::Security::PipelineExecutionPolicyConfigLink.for_project(project).none?

        ::Security::SyncLinkedPipelineExecutionPolicyConfigsWorker
          .perform_async(project.id, current_user.id, oldrev, newrev, ref)
      end

      def enqueue_elasticsearch_indexing
        return unless should_index_commits?

        project.repository.index_commits_and_blobs
      end

      def enqueue_zoekt_indexing
        return false unless ::Gitlab::CurrentSettings.zoekt_indexing_enabled?
        return false unless default_branch?
        return false unless project.use_zoekt?

        project.repository.async_update_zoekt_index
      end

      def enqueue_knowledge_graph_code_indexing
        return false unless default_branch?
        return false unless project.knowledge_graph_indexing_enabled?

        ::Analytics::KnowledgeGraph::CodeIndexingWorker.perform_async(
          project.id,
          ref,
          newrev
        )
      end

      def enqueue_code_embedding_indexing
        return false unless default_branch?

        repository = Ai::ActiveContext::Code::Repository.find_by_project_id(project.id)
        return false unless repository&.ready?

        ::Ai::ActiveContext::Code::RepositoryIndexWorker.perform_with_push_delay(repository)
      end

      def enqueue_update_external_pull_requests
        return unless project.mirror?
        return unless params.fetch(:create_pipelines, true)

        UpdateExternalPullRequestsWorker.perform_async(
          project.id,
          current_user.id,
          ref
        )
      end

      def should_index_commits?
        return false unless default_branch?

        project.use_elasticsearch?
      end

      def enqueue_repository_xray
        return if removing_branch?
        return unless default_branch? && project.duo_features_enabled

        scan_lease = repository_xray_lease(:scan, REPOSITORY_XRAY_SCAN_PERIOD)
        return ::Ai::RepositoryXray::ScanDependenciesWorker.perform_async(project.id) if scan_lease.try_obtain

        # Scan once more when the period ends, so pushes made during it are picked up without waiting for another push.
        delay = scan_lease.ttl || REPOSITORY_XRAY_SCAN_PERIOD.to_i
        return unless repository_xray_lease(:delayed_scan, delay).try_obtain

        ::Ai::RepositoryXray::ScanDependenciesWorker.perform_in(delay, project.id)
      end

      def repository_xray_lease(name, timeout)
        ::Gitlab::ExclusiveLease.new("repository_xray_#{name}:#{project.id}", timeout: timeout.to_i)
      end
    end
  end
end
