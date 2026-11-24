# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class WorkflowContextGenerationService
      include ::Gitlab::Utils::StrongMemoize

      AI_WORKFLOWS_SCOPES = (::Gitlab::Auth::AI_WORKFLOW_SCOPES + [::Gitlab::Auth::MCP_SCOPE]).to_set.freeze
      EMPTY_TOOL_POLICIES = ::Ai::ToolRules::SessionPolicyService::EMPTY_TOOL_POLICIES

      # `surface` must come from Ai::ToolRules::GovernanceSurface.
      def initialize( # rubocop:disable Metrics/ParameterLists -- all keyword args
        current_user:, organization:, surface:, workflow_definition: nil, container: nil, service_account: nil,
        trigger_source: nil, additional_context: nil, workflow_id: nil)
        @current_user = current_user
        @container = container
        @organization = organization
        @service_account = service_account
        @workflow_definition = workflow_definition
        @surface = surface
        @trigger_source = trigger_source
        @additional_context = additional_context
        @workflow_id = workflow_id
      end

      def generate_oauth_token
        ::Ai::DuoWorkflows::CreateOauthAccessTokenService.new(
          current_user: current_user,
          organization: organization,
          workflow_definition: workflow_definition,
          workflow_id: workflow_id
        ).execute
      end

      def generate_composite_oauth_token(
        expires_in: ::Ai::DuoWorkflows::CreateCompositeOauthAccessTokenService::TOKEN_EXPIRES_IN)
        ::Ai::DuoWorkflows::CreateCompositeOauthAccessTokenService.new(
          current_user: current_user,
          organization: organization,
          service_account: service_account,
          container: container,
          workflow_id: workflow_id,
          expires_in: expires_in
        ).execute
      end

      # A caller with no workflow to anchor to must not sign a policy resolved from a namespace
      # the caller named.
      def generate_workflow_token(
        flow_config_id: nil, flow_version: nil, flow_config_schema_version: nil, flow_config: nil,
        workflow_id: nil, resolve_governance: true)
        feature_setting = duo_agent_platform_feature_setting
        tool_policies = resolve_governance ? resolve_tools : EMPTY_TOOL_POLICIES

        ::Ai::DuoWorkflow::DuoWorkflowService::Client.new(
          duo_workflow_service_url: Gitlab::DuoWorkflow::Client.url_for(
            feature_setting: feature_setting,
            user: current_user
          ),
          current_user: current_user,
          secure: Gitlab::DuoWorkflow::Client.secure?(feature_setting: feature_setting),
          feature_setting: feature_setting,
          container: container,
          pre_approved_tools: tool_policies[:pre_approved_tools],
          denied_tools: tool_policies[:denied_tools],
          ask_tools: tool_policies.fetch(:ask_tools, []),
          # Only a governed policy carries the ceiling, matching ConnectionConfigService.
          ceiling: tool_policies != EMPTY_TOOL_POLICIES && governance_ceiling_enabled?
        ).generate_token(
          flow_config_id: flow_config_id,
          flow_version: flow_version,
          flow_config_schema_version: flow_config_schema_version,
          flow_config: flow_config,
          workflow_id: workflow_id
        )
      end

      # expires_in only applies on the composite branch; the autonomous and generate_oauth_token
      # branches silently discard it and always mint their own default lifetime.
      def generate_oauth_token_with_composite_identity_support(
        expires_in: ::Ai::DuoWorkflows::CreateCompositeOauthAccessTokenService::TOKEN_EXPIRES_IN)
        if autonomous_execution?
          generate_autonomous_oauth_token
        elsif composite_identity_enabled?
          generate_composite_oauth_token(expires_in: expires_in)
        else
          generate_oauth_token
        end
      end

      def generate_autonomous_oauth_token
        ::Ai::DuoWorkflows::CreateAutonomousOauthAccessTokenService.new(
          service_account: service_account,
          organization: organization,
          container: container,
          trigger_source: trigger_source
        ).execute
      end

      # Returns true when the given access_token already carries all required AI workflow
      # scopes, so a new OAuth token does not need to be created for this request.
      def already_scoped_for_ai_workflows?(access_token)
        return false unless access_token&.scopes

        return false unless ::Ai::DuoWorkflows::WorkflowTokenScope.allows_workflow?(access_token.scopes, workflow_id)

        token_scopes = ::Ai::DuoWorkflows::WorkflowTokenScope.without(access_token.scopes).map(&:to_sym).to_set

        # StatelessAccessToken JWTs carry composite identity in the gitlab.identities
        # claim, not a `user:<id>` scope, so composite-ness must be read from the
        # token directly rather than trusted from composite_identity_enabled? alone.
        if access_token.is_a?(::Authn::Tokens::StatelessAccessToken)
          return false unless token_scopes == AI_WORKFLOWS_SCOPES

          token_is_composite = access_token.identities.present?
          return false if composite_identity_mismatch?(token_is_composite)

          # Non-composite: the subject must be the requesting user, mirroring
          # the service account subject check on the composite path below.
          return access_token.user == current_user unless composite_identity_enabled?

          # Also confirm the token's own subject is this service account: two
          # service accounts could otherwise share a reusable token merely by
          # embedding the same human in their identities claim.
          return false unless access_token.user == @service_account

          return access_token.identity_user == current_user
        end

        expected_scopes = if composite_identity_enabled?
                            (AI_WORKFLOWS_SCOPES + [:"user:#{current_user.id}"]).to_set
                          else
                            AI_WORKFLOWS_SCOPES
                          end

        token_scopes == expected_scopes
      end

      def duo_agent_platform_feature_setting
        ::Ai::FeatureSettingSelectionService
          .new(current_user, ai_feature, container&.root_ancestor)
          .execute.payload
      end
      strong_memoize_attr :duo_agent_platform_feature_setting

      private

      attr_reader :current_user, :container, :organization, :workflow_definition, :service_account, :surface,
        :trigger_source, :additional_context, :workflow_id

      # Autonomous execution: SA acts alone with no human user. Keyed on
      # trigger_source because an SA authenticating as itself is the normal state
      # for any SA-owned token, so the identity check alone would also reroute
      # pre-existing API callers.
      def autonomous_execution?
        return false unless Workflow::AUTONOMOUS_TRIGGER_SOURCES.include?(trigger_source.to_s)

        current_user&.service_account? && service_account == current_user
      end

      def composite_identity_enabled?
        !!@service_account&.composite_identity_enforced
      end

      # True when the flag and the token's actual identities claim disagree
      # about whether this should be a composite-identity token.
      def composite_identity_mismatch?(token_is_composite)
        composite_identity_enabled? != token_is_composite
      end

      def ai_feature
        flow = ::Ai::Catalog::FoundationalFlow[workflow_definition]
        flow&.resolve_ai_feature(
          current_user: current_user, container: container, additional_context: additional_context
        )&.to_sym ||
          :duo_agent_platform
      end

      def governance_ceiling_enabled?
        ::Ai::DuoWorkflows::GovernanceCeiling.enabled?(container)
      end

      def resolve_tools
        ::Ai::ToolRules::SessionPolicyService.new(container: container, surface: surface).execute
      end
    end
  end
end
