# frozen_string_literal: true

module Ai
  # Computes the list of capabilities the instance advertises for Duo Agent
  # Platform flows (for example: checkpoint pagination, advanced search, or
  # the default flow a new Duo CLI session should run).
  #
  # This intentionally mirrors a subset of the `server_capabilities` computed
  # by the REST `direct_access` endpoint
  # (ee/lib/api/ai/duo_workflows/workflows.rb#compute_server_capabilities) and
  # is meant to eventually replace it. Capabilities Rails can compute locally
  # are combined with capabilities that require a live round trip to the Duo
  # Workflow Service (via `ListCapabilities`), such as `tool_call_approval`.
  class FlowsMetadataService
    # DWS advertises these regardless of whether the caller's namespace/project
    # has opted in to per-session tool approval; filter them out here to
    # mirror `Api::Ai::DuoWorkflows::Workflows#tool_approval_for_session_enabled?`.
    TOOL_APPROVAL_CAPABILITIES = %w[tool_call_approval tool_call_pattern_approval].freeze

    # DWS capabilities are effectively static per Duo Workflow Service
    # deployment, so caching them avoids a gRPC round trip on every
    # `aiFlowsMetadata` request.
    DWS_CAPABILITIES_CACHE_KEY = 'ai_flows_metadata:dws_capabilities'
    DWS_CAPABILITIES_CACHE_EXPIRATION = 1.hour

    # @param current_user [User, nil]
    # @param namespace [Namespace, nil] a group or personal namespace to scope
    #   capabilities to. Ignored (falls back to instance-wide) when `project`
    #   is also given.
    # @param project [Project, nil] a project to scope capabilities to. Takes
    #   precedence over `namespace` when both are given, mirroring the REST
    #   `direct_access` endpoint's `project || namespace` precedence.
    # @param client_type [Symbol, nil] the calling surface (:cli or :ide).
    #   Controls which feature flag gates the `duo_developer` capability so
    #   CLI and IDE rollouts can be managed independently. When nil, falls
    #   back to duo_cli_default_flow for backwards compatibility.
    def initialize(current_user:, namespace: nil, project: nil, client_type: nil)
      @current_user = current_user
      @namespace = namespace
      @project = project
      @client_type = client_type
    end

    def execute
      [
        { name: 'job_trace_pagination', metadata: nil },
        { name: 'tool_call_approval_source', metadata: nil },
        { name: 'incremental_checkpoints', metadata: nil },
        { name: 'incremental_checkpoints_only', metadata: nil },
        { name: 'idle_status_event', metadata: nil },
        advanced_search_capability,
        duo_developer_capability,
        duo_auto_mode_capability,
        image_response_capability,
        *dws_capabilities
      ].compact
    end

    private

    attr_reader :current_user, :namespace, :project, :client_type

    def advanced_search_capability
      return unless ::Gitlab::CurrentSettings.search_using_elasticsearch?(scope: project || namespace)

      { name: 'advanced_search', metadata: nil }
    end

    # Tool-read images: the client returns them only when the instance says it can carry them.
    def image_response_capability
      return unless current_user
      return unless Feature.enabled?(:dap_tool_image_input, current_user)

      { name: 'image_response', metadata: nil }
    end

    # TODO: `flow_config_id`/`flow_config_schema_version`/`flow_version`
    # are hardcoded below because there is no shared source of truth for
    # them yet. Extract them into a shared constant/registry:
    # https://gitlab.com/gitlab-org/gitlab/-/work_items/605476
    def duo_developer_capability
      return unless current_user
      return unless duo_developer_flag_enabled?

      {
        name: 'duo_developer',
        metadata: {
          flow_config_id: 'developer',
          flow_config_schema_version: 'v1',
          flow_version: duo_developer_flow_version
        }
      }
    end

    def duo_developer_flag_enabled?
      # nil: caller predates clientType; keep CLI behaviour until migrated.
      # TODO: remove once all CLI clients pass clientType:
      # https://gitlab.com/gitlab-org/gitlab/-/work_items/630562
      if client_type == :ide
        Feature.enabled?(:duo_ide_default_flow, current_user)
      else
        Feature.enabled?(:duo_cli_default_flow, current_user)
      end
    end

    def duo_developer_flow_version
      # duo_cli_local_review is CLI-only; IDE always gets the base version.
      return '2.1.0-interactive' if client_type != :ide && Feature.enabled?(:duo_cli_local_review, current_user)

      '2.0.0-interactive'
    end

    def duo_auto_mode_capability
      return unless duo_auto_mode_enabled?

      { name: 'duo_auto_mode', metadata: nil }
    end

    def duo_auto_mode_enabled?
      ::Ai::DuoSettings::AutoMode.consented?(container: project || namespace)
    end

    # Fetches capabilities that only the Duo Workflow Service knows about
    # (for example `tool_call_approval`). Fails open: any error talking to
    # DWS results in an empty list rather than failing the whole query.
    def dws_capabilities
      return [] unless current_user

      capabilities = cached_dws_capabilities

      return capabilities if tool_approval_for_session_enabled?

      capabilities.reject { |capability| TOOL_APPROVAL_CAPABILITIES.include?(capability[:name]) }
    end

    # Only successful responses are cached, so a transient DWS outage is
    # retried on the next request instead of being remembered as "no
    # capabilities" for the remainder of the cache TTL.
    def cached_dws_capabilities
      Rails.cache.read(DWS_CAPABILITIES_CACHE_KEY) || fetch_and_cache_dws_capabilities
    end

    def fetch_and_cache_dws_capabilities
      response = duo_workflow_service_client.list_capabilities

      unless response.success?
        Gitlab::AppLogger.error("FlowsMetadataService ListCapabilities failed: #{response.message}")
        return []
      end

      capabilities = response.payload[:capabilities]
      Rails.cache.write(DWS_CAPABILITIES_CACHE_KEY, capabilities, expires_in: DWS_CAPABILITIES_CACHE_EXPIRATION)
      capabilities
    rescue StandardError => e
      Gitlab::AppLogger.error("FlowsMetadataService ListCapabilities failed: #{e.message}")
      []
    end

    def duo_workflow_service_client
      feature_setting = resolve_feature_setting

      ::Ai::DuoWorkflow::DuoWorkflowService::Client.new(
        duo_workflow_service_url: ::Gitlab::DuoWorkflow::Client.url_for(
          feature_setting: feature_setting, user: current_user
        ),
        current_user: current_user,
        secure: ::Gitlab::DuoWorkflow::Client.secure?(feature_setting: feature_setting),
        feature_setting: feature_setting,
        container: project || namespace
      )
    end

    def resolve_feature_setting
      root_namespace = (project || namespace)&.root_ancestor
      return unless root_namespace

      ::Ai::FeatureSettingSelectionService.new(
        current_user,
        ::Ai::ModelSelection::FeaturesConfigurable.workflow_feature_name,
        root_namespace
      ).execute.payload
    end

    def tool_approval_for_session_enabled?
      ::Ai::DuoSettings::CascadingSettingResolver.enabled?(
        project: project, namespace: namespace, attribute: :tool_approval_for_session_enabled?
      )
    end
  end
end
