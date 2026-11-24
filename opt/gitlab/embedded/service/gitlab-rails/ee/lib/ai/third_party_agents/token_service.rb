# frozen_string_literal: true

module Ai
  module ThirdPartyAgents
    class TokenService
      include Gitlab::Llm::Concerns::Logger

      DEFAULT_TIMEOUT = 30.seconds
      TOKEN_TIMEOUT = 3.seconds

      DirectAccessError = Class.new(StandardError)

      def initialize(current_user:, organization: nil, project: nil, agent_name: nil, workflow_id: nil)
        @current_user = current_user
        @organization = organization
        @project = project
        @agent_name = agent_name
        @workflow_id = workflow_id
      end

      def direct_access_token
        log_info(message: 'Creating user access token',
          event_name: 'user_token_created',
          ai_component: 'third_party_agents'
        )

        governing_namespace = current_user.governing_namespace(project)

        if Gitlab::Saas.feature_available?(:gitlab_duo_saas_only)
          if governing_namespace.nil?
            return error_response('Missing default GitLab Duo namespace user preference', nil,
              reason: :missing_duo_namespace)
          end

          # Usage is billed to the governing namespace, so its Duo setting gates token creation.
          unless governing_namespace.namespace_settings&.duo_features_enabled
            return error_response('GitLab Duo features are disabled for the billing namespace', nil,
              reason: :duo_features_disabled)
          end
        end

        token_timeout = TOKEN_TIMEOUT

        response = Gitlab::HTTP.post(
          Gitlab::AiGateway.access_token_url(nil),
          headers: ai_gateway_headers(governing_namespace),
          body: nil,
          timeout: token_timeout,
          allow_local_requests: true,
          stream_body: false
        )

        return gateway_error_response(response) unless response.success?
        return error_response('Token is missing in response', response) unless response['token'].present?

        log_audit_event(response['token'], response['expires_at'])

        ServiceResponse.success(
          message: "Direct Access Token Generated",
          payload: {
            headers: public_headers(governing_namespace),
            token: response['token'],
            expires_at: response['expires_at']
          }
        )

      rescue *Gitlab::HTTP::HTTP_ERRORS => e
        ServiceResponse
          .error(message: 'An HTTP error occurred when creating a Direct Access Token.')
          .track_exception(
            as: e.class,
            agent_name: agent_name,
            workflow_id: workflow_id,
            project_id: project&.id,
            namespace_id: project&.namespace_id
          )
      end

      private

      attr_reader :current_user, :project, :organization, :agent_name, :workflow_id

      def log_audit_event(token, expires_at)
        scopes = decode_token_scopes(token)

        ::Gitlab::Audit::Auditor.audit(
          name: 'third_party_agent_token_created',
          author: current_user,
          scope: current_user,
          target: current_user,
          message: "Generated third-party agent access token",
          additional_details: {
            token_expires_at: expires_at,
            token_scopes: scopes,
            agent_name: agent_name,
            workflow_id: workflow_id,
            project_id: project&.id,
            namespace_id: project&.namespace_id,
            organization_id: organization&.id
          }.compact
        )
      end

      def decode_token_scopes(token)
        payload, _header = JWT.decode(token, nil, false)
        scopes = payload['scopes']
        Array.wrap(scopes).presence
      rescue JWT::DecodeError, ArgumentError
        nil
      end

      def ai_gateway_headers(governing_namespace)
        Gitlab::AiGateway.headers(
          user: current_user,
          organization_id: organization&.id,
          unit_primitive_name: :ai_gateway_model_provider_proxy,
          namespace_id: project&.namespace_id,
          project_id: project&.id,
          governing_namespace_id: governing_namespace&.id,
          ai_feature_name: :duo_workflow,
          extra_claims: model_allowlist_claims(governing_namespace)
        )
      end

      # AI gateway copies these claims into the minted token, and its proxy enforces them per request.
      def model_allowlist_claims(governing_namespace)
        # Self-managed tokens are not self-signed, so extra claims would be dropped.
        return {} unless Gitlab::Saas.feature_available?(:gitlab_duo_saas_only)

        result = ::Ai::FeatureSettingSelectionService.new(
          current_user, ::Ai::ModelSelection::FeaturesConfigurable.agentic_chat_feature_name, governing_namespace
        ).execute
        return {} unless result.success?

        refs = ::Ai::ModelSelection::UserModelSelection
          .for(current_user, feature_setting: result.payload)
          .enforced_model_refs
        return {} if refs.nil?

        { gitlab_allowed_model_refs: refs }
      end

      def public_headers(governing_namespace)
        Gitlab::AiGateway.public_headers(
          user: current_user,
          ai_feature_name: :duo_workflow,
          organization_id: organization&.id,
          unit_primitive_name: :ai_gateway_model_provider_proxy,
          namespace_id: project&.namespace_id,
          project_id: project&.id,
          governing_namespace_id: governing_namespace&.id
        ).merge(
          'x-gitlab-unit-primitive' => 'ai_gateway_model_provider_proxy',
          'x-gitlab-authentication-type' => 'oidc'
        )
      end

      def gateway_error_response(response)
        if response.code == 402
          return error_response(
            'Token creation failed: not enough GitLab Credits. Contact your administrator for more credits.',
            response, reason: :insufficient_credits)
        end

        error_response('Token creation failed', response)
      end

      def error_response(message, response, reason: nil)
        error_context = {}.tap do |h|
          next if response.nil?

          h[:ai_gateway_response_code] = response.code
          if response.parsed_response.is_a?(String)
            h[:ai_gateway_error_detail] = response.parsed_response
          elsif response.respond_to?(:dig) && response.parsed_response&.dig("detail")
            h[:ai_gateway_error_detail] = response.parsed_response["detail"]
          end
        end

        Gitlab::ErrorTracking.track_exception(DirectAccessError.new(message), error_context)

        ServiceResponse.error(message: message, reason: reason)
      end
    end
  end
end
