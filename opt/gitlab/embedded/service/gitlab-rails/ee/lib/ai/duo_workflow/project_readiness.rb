# frozen_string_literal: true

module Ai
  module DuoWorkflow
    # Read-only view of how ready a project is to run Duo Agent Platform flows, backing
    # the readiness rows in Settings > General > GitLab Duo.
    class ProjectReadiness
      include ::Gitlab::Utils::StrongMemoize
      include Concerns::RunnerCheck
      include Concerns::McpServers

      AGENT_CONFIG_PATH = ::Gitlab::DuoAgentPlatform::Config::CONFIG_FILE_NAME
      # The bounds GraphQL requires for its blobPath filter: merge_request_diff_files has no index
      # on old_path, so without them a miss reads the latest diff of every open merge request.
      AGENT_CONFIG_MERGE_REQUEST_WINDOW = 30.days

      def initialize(project, user)
        @project = project
        @user = user
      end

      def platform_enabled?
        ::Ai::DuoWorkflow.duo_agent_platform_available?(project)
      end
      strong_memoize_attr :platform_enabled?

      def agent_config_present?
        ::Gitlab::DuoAgentPlatform::Config.new(project).config_present?
      end
      strong_memoize_attr :agent_config_present?

      # Not read from AgentConfigWorkflowTracker: its cache entry expires while a
      # draft merge request can still be open.
      def agent_config_merge_request
        return if agent_config_present?

        MergeRequestsFinder.new(
          user,
          project_id: project.id,
          state: 'opened',
          target_branch: project.default_branch,
          created_after: AGENT_CONFIG_MERGE_REQUEST_WINDOW.ago,
          blob_path: AGENT_CONFIG_PATH,
          sort: 'created_asc'
        ).execute.first
      end
      strong_memoize_attr :agent_config_merge_request

      def agent_config_workflow_id
        return if agent_config_present?

        AgentConfigWorkflowTracker.new(project).active_workflow&.id
      end
      strong_memoize_attr :agent_config_workflow_id

      def repository_empty?
        project.empty_repo?
      end
      strong_memoize_attr :repository_empty?

      # Without a flow consumer the run fails with a message meaningless to maintainers,
      # so the action is hidden instead.
      def generate_available?
        return false if repository_empty?

        catalog_item = ::Ai::Catalog::FoundationalFlow.developer_v1.catalog_item

        !!catalog_item&.consumers&.for_projects(project)&.exists?
      end
      strong_memoize_attr :generate_available?

      private

      attr_reader :project, :user

      alias_method :container, :project

      def runner_scope
        project_runner_scope(project)
      end

      def mcp_consumer_params
        { project_id: project.id }
      end

      # The same namespace a project run passes to McpConfigService.
      def mcp_block_namespace
        project.project_namespace
      end
    end
  end
end
