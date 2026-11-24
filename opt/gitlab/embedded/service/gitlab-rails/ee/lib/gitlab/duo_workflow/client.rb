# frozen_string_literal: true

module Gitlab
  module DuoWorkflow
    class Client
      # Duo Workflow Service sends this capability when it can fetch a flow from GitLab.
      FETCH_FLOW_CONFIG_CAPABILITY = 'fetch_flow_config'

      def self.url(user:)
        self_hosted_url || cloud_connected_url(user: user)
      end

      def self.cloud_connected_url(user:)
        Gitlab.config.duo_workflow.service_url || default_service_url(user: user)
      end

      def self.default_service_url(user:)
        if Feature.enabled?(:duo_workflow_cloud_connector_url, user)
          return "#{::CloudConnector::Config.host}:#{::CloudConnector::Config.port}"
        end

        subdomain = ::CloudConnector::Config.host.include?('staging') ? '.staging' : ''

        # Cloudflare has been disabled until
        # gets resolved https://gitlab.com/gitlab-org/gitlab/-/issues/509586
        # "#{::CloudConnector::Config.host}:#{::CloudConnector::Config.port}"
        "duo-workflow-svc#{subdomain}.runway.gitlab.net:#{::CloudConnector::Config.port}"
      end

      def self.url_for(feature_setting:, user:)
        if gitlab_hosted_service?(feature_setting)
          cloud_connected_url(user: user)
        else
          self_hosted_url
        end
      end

      # A service that the instance runs can be older than GitLab: the self-hosted one, or
      # one set in the configuration file. The default GitLab-hosted service is always current.
      def self.self_managed_service?(feature_setting)
        !gitlab_hosted_service?(feature_setting) || Gitlab.config.duo_workflow.service_url.present?
      end

      # A service that the instance runs must say that it can fetch the flow.
      # @param capabilities [Array<String>, nil] the capabilities from a token response
      def self.fetches_flow_config?(feature_setting, capabilities)
        return true unless self_managed_service?(feature_setting)

        Array(capabilities).include?(FETCH_FLOW_CONFIG_CAPABILITY)
      end

      def self.self_hosted_url
        ::Gitlab::CurrentSettings.duo_agent_platform_service_url.presence
      end

      def self.secure?(feature_setting: nil)
        return ::Gitlab::CurrentSettings.self_hosted_duo_agent_platform_service_secure if feature_setting&.self_hosted?

        !!Gitlab.config.duo_workflow.secure
      end

      def self.debug_mode?
        !!Gitlab.config.duo_workflow.debug
      end

      def self.cloud_connector_headers( # rubocop:disable Metrics/ParameterLists -- each signed claim is its own keyword
        user:, feature_setting: nil, tool_access_policies: {}, subject: user,
        governing_namespace_id: nil, workflow_id: nil, flow_config_id: nil, flow_config_digest: nil, **kwargs)
        # binds_workflow tells DWS that a token from this instance without workflow_id is unbound.
        extra_claims = { tool_access_policies: tool_access_policies.to_json, binds_workflow: true }
        # Scopes the token to the workflow it was issued for. Carried only when the instance
        # self-signs, since CloudConnector::Tokens keeps extra claims on that path alone.
        extra_claims[:workflow_id] = workflow_id.to_s if workflow_id
        # Lets DWS authorize models reserved for a gitlab_hosted_runner_only flow. Like workflow_id,
        # only kept when the instance self-signs the token, as on GitLab.com.
        extra_claims[:flow_config_id] = flow_config_id if flow_config_id.present?
        # Binds a fetched AI Catalog flow to its definition. Like workflow_id, only kept when self-signed.
        extra_claims[:flow_config_digest] = flow_config_digest if flow_config_digest.present?
        governing_namespace = ::Namespace.find_by_id(governing_namespace_id)
        extra_claims[:gitlab_paid_credit_models_allowed] =
          !::Ai::ModelSelection::CreditGate.new(governing_namespace).applies?

        ai_feature_name = :duo_workflow
        unit_primitive_name = :duo_agent_platform

        auth_response = Gitlab::AiGateway.resolve_auth_response(
          user: user,
          ai_feature_name: ai_feature_name,
          unit_primitive_name: unit_primitive_name,
          feature_setting: feature_setting
        )

        token = Gitlab::AiGateway.cloud_connector_token(
          unit_primitive_name,
          user,
          feature_setting: feature_setting,
          root_namespace_id: governing_namespace_id,
          enablement_type: Gitlab::AiGateway.enablement_type_for(auth_response),
          extra_claims: extra_claims
        )

        headers = Gitlab::AiGateway
          .public_headers(user: user, feature_setting: feature_setting, ai_feature_name: ai_feature_name,
            unit_primitive_name: unit_primitive_name, subject: subject,
            governing_namespace_id: governing_namespace_id, auth_response: auth_response, **kwargs)
          .transform_keys(&:downcase)
          .merge(
            'authorization' => "Bearer #{token}",
            'x-gitlab-authentication-type' => 'oidc'
          )

        proof = restricted_flow_proof(feature_setting, flow_config_id, workflow_id)
        headers['x-gitlab-restricted-flow-proof'] = proof if proof
        headers
      end

      # The Cloud Connector token of a GitLab Dedicated instance carries no extra claims, so the
      # restricted flow travels in a separate proof that binds the run to this instance.
      # Only the GitLab-hosted DWS checks it.
      private_class_method def self.restricted_flow_proof(feature_setting, flow_config_id, workflow_id)
        return unless flow_config_id.present? && workflow_id && gitlab_hosted_service?(feature_setting)
        return unless ::Gitlab::Dedicated.feature_available?(:restricted_flow_proof_tokens)

        ::CloudConnector::RestrictedFlowProof.new(flow_config_id: flow_config_id, workflow_id: workflow_id).token
      end

      # Matches url_for: a request goes to cloud_connected_url unless the feature setting is self-hosted.
      private_class_method def self.gitlab_hosted_service?(feature_setting)
        !feature_setting&.self_hosted?
      end

      def self.metadata(user, namespace: nil, project: nil)
        root_namespace = namespace&.root_ancestor

        {
          extended_logging: enable_extended_logging?(user, namespace: namespace),
          is_team_member:
            ::Gitlab::Tracking::StandardContext.new.gitlab_team_member?(user&.id),
          tool_approval_for_session_enabled: tool_approval_for_session_enabled?(namespace: namespace,
            project: project),
          rootNamespaceId: root_namespace&.id&.to_s
        }
      end

      private_class_method def self.tool_approval_for_session_enabled?(namespace: nil, project: nil)
        return project.project_setting.tool_approval_for_session_enabled? if project

        return false unless namespace

        namespace.namespace_settings&.tool_approval_for_session_enabled?
      end

      def self.enable_extended_logging?(user, namespace: nil)
        # For a self-hosted Duo instance, return the value of the
        # instance setting.
        return ::Gitlab::CurrentSettings.enabled_instance_verbose_ai_logs if self_hosted_url

        # Check if the feature flag is enabled for the user - this overrides namespace check
        return true if Feature.enabled?(:duo_workflow_extended_logging, user)

        # If a namespace is provided, return the value of the namespace setting
        return namespace.ai_usage_data_collection_enabled if namespace

        false
      end
    end
  end
end
