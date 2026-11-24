# frozen_string_literal: true

require 'grpc'
require 'gitlab/duo_workflow_service'
require 'google/protobuf'
require 'json'

module Ai
  module DuoWorkflow
    module DuoWorkflowService
      class Client
        include Gitlab::Utils::StrongMemoize

        ERROR_MSG_SERVICE_URL_NOT_CONFIGURED = 'Duo Workflow service URL is not configured'
        ERROR_MSG_FLOW_CONFIG_BLANK = 'Flow definition is missing and cannot be validated'
        ERROR_REASON_SERVICE_UNAVAILABLE = :service_unavailable
        ERROR_REASON_INVALID_FLOW_CONFIG = :invalid_config
        VALIDATE_FLOW_CONFIG_TIMEOUT = 10
        GENERATE_TOKEN_TIMEOUT = 20
        LIST_TOOLS_TIMEOUT = 10
        LIST_CAPABILITIES_TIMEOUT = 10

        def initialize( # rubocop:disable Metrics/ParameterLists -- the ceiling travels with the three policy lists it caps
          duo_workflow_service_url:,
          current_user:,
          secure:,
          feature_setting: nil,
          container: nil,
          pre_approved_tools: [],
          denied_tools: [],
          ask_tools: [],
          ceiling: false)
          @duo_workflow_service_url = duo_workflow_service_url
          @current_user = current_user
          @secure = secure
          @feature_setting = feature_setting
          @container = container
          @pre_approved_tools = pre_approved_tools
          @denied_tools = denied_tools
          @ask_tools = ask_tools
          @ceiling = ceiling
        end

        def track_self_hosted_client_event(request_id:, feature_qualified_name:, feature_ai_catalog_item: false)
          # Billing events always go to GitLab's cloud Duo Workflow Service, which only trusts the
          # CustomersDot-issued instance JWT. Never fall back to a self-signed token here.
          token = ::CloudConnector::Tokens.cloud_connector_token
          return ServiceResponse.error(message: 'CustomersDot-issued instance JWT is unavailable') if token.blank?

          stub = ::DuoWorkflowService::DuoWorkflow::Stub.new(
            duo_workflow_service_url,
            channel_credentials
          )

          event = ::DuoWorkflowService::TrackSelfHostedClientEvent.new(
            requestID: request_id,
            workflowID: request_id,
            featureQualifiedName: feature_qualified_name,
            featureAiCatalogItem: feature_ai_catalog_item
          )

          responses = stub.track_self_hosted_execute_workflow([event], metadata: metadata(bearer_token: token))
          responses.first # consume the single ack

          ServiceResponse.success(message: "Billing event tracked")
        rescue StandardError => e
          ServiceResponse.error(message: e.message)
        end

        def generate_token(
          flow_config_id: nil, flow_version: nil, flow_config_schema_version: nil, flow_config: nil, workflow_id: nil)
          return ServiceResponse.error(message: ERROR_MSG_SERVICE_URL_NOT_CONFIGURED) if duo_workflow_service_url.blank?

          begin
            request = ::DuoWorkflowService::GenerateTokenRequest.new(
              flow_config_id: flow_config_id,
              flow_version: flow_version,
              flow_config_schema_version: flow_config_schema_version,
              flow_config: flow_config && Google::Protobuf::Struct.decode_json(flow_config.to_json),
              # camelCase because that is how the contract spells this proto field.
              workflowID: workflow_id&.to_s
            )
            response = grpc_stub.generate_token(
              request,
              metadata: metadata,
              deadline: GRPC::Core::TimeConsts.from_relative_time(GENERATE_TOKEN_TIMEOUT)
            )
          rescue GRPC::DeadlineExceeded => e
            Gitlab::AppLogger.error("DWS GenerateToken timed out after #{GENERATE_TOKEN_TIMEOUT}s: #{e.message}")
            return ServiceResponse.error(message: e.message)
          rescue StandardError => e
            return ServiceResponse.error(message: e.message)
          end

          # Extract capabilities if present (backward compatible)
          server_capabilities = response.respond_to?(:server_capabilities) ? response.server_capabilities.to_a : []

          ServiceResponse.success(
            message: "JWT Generated",
            payload: {
              token: response.token,
              expires_at: response.expiresAt,
              capabilities: server_capabilities
            }
          )
        end

        def validate_flow_config(flow_config:)
          if duo_workflow_service_url.blank?
            return ServiceResponse.error(
              message: ERROR_MSG_SERVICE_URL_NOT_CONFIGURED,
              reason: ERROR_REASON_SERVICE_UNAVAILABLE
            )
          end

          if flow_config.blank?
            return ServiceResponse.error(
              message: ERROR_MSG_FLOW_CONFIG_BLANK,
              reason: ERROR_REASON_INVALID_FLOW_CONFIG
            )
          end

          begin
            request = ::DuoWorkflowService::ValidateFlowConfigRequest.new(
              flow_config: Google::Protobuf::Struct.decode_json(flow_config.to_json)
            )
            response = grpc_stub.validate_flow_config(
              request,
              metadata: metadata,
              deadline: GRPC::Core::TimeConsts.from_relative_time(VALIDATE_FLOW_CONFIG_TIMEOUT)
            )
          rescue StandardError => e
            Gitlab::AppLogger.error("DWS ValidateFlowConfig failed: #{e.message}")
            return ServiceResponse.error(
              message: 'Unable to validate flow configuration. Duo Workflow Service is currently unavailable.',
              reason: ERROR_REASON_SERVICE_UNAVAILABLE
            )
          end

          if response.valid
            ServiceResponse.success
          else
            ServiceResponse.error(message: response.errors.to_a, reason: ERROR_REASON_INVALID_FLOW_CONFIG)
          end
        end

        def list_tools
          return ServiceResponse.error(message: ERROR_MSG_SERVICE_URL_NOT_CONFIGURED) if duo_workflow_service_url.blank?

          begin
            response = grpc_stub.list_tools(
              ::DuoWorkflowService::ListToolsRequest.new,
              metadata: metadata,
              deadline: GRPC::Core::TimeConsts.from_relative_time(LIST_TOOLS_TIMEOUT)
            )
            data = Gitlab::Json.safe_parse(Google::Protobuf.encode_json(response))
          rescue StandardError => e
            return ServiceResponse.error(message: e.message)
          end

          ServiceResponse.success(
            message: "Tools listed",
            payload: data.slice("tools", "evalDataset")
          )
        end

        def list_capabilities
          return ServiceResponse.error(message: ERROR_MSG_SERVICE_URL_NOT_CONFIGURED) if duo_workflow_service_url.blank?

          begin
            response = grpc_stub.list_capabilities(
              ::DuoWorkflowService::ListCapabilitiesRequest.new,
              metadata: metadata,
              deadline: GRPC::Core::TimeConsts.from_relative_time(LIST_CAPABILITIES_TIMEOUT)
            )
          rescue StandardError => e
            return ServiceResponse.error(message: e.message)
          end

          capabilities = response.capabilities.map do |capability|
            {
              name: capability.name,
              metadata: capability.metadata.presence && Gitlab::Json.safe_parse(capability.metadata)
            }
          end

          ServiceResponse.success(
            message: "Capabilities listed",
            payload: { capabilities: capabilities }
          )
        end

        private

        attr_reader :duo_workflow_service_url, :current_user, :feature_setting, :container

        def grpc_stub
          ::DuoWorkflowService::DuoWorkflow::Stub.new(
            duo_workflow_service_url,
            channel_credentials
          )
        end
        strong_memoize_attr :grpc_stub

        def governing_namespace
          current_user&.governing_namespace(container)
        end
        strong_memoize_attr :governing_namespace

        # NOTE: gRPC-Ruby validates metadata keys against the lowercase HTTP/2 form and
        # rejects mixed-case keys rather than normalizing them. See:
        # https://github.com/grpc/grpc/blob/master/src/ruby/ext/grpc/rb_call.c
        # https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md
        #
        # Although HTTP header names are case-insensitive semantically, gRPC over HTTP/2
        # requires metadata/header names to use lowercase. Keep all keys returned here lowercase.
        def metadata(bearer_token: nil)
          Gitlab::AiGateway.headers(
            user: current_user,
            unit_primitive_name: :duo_agent_platform,
            governing_namespace_id: governing_namespace&.id,
            organization_id: governing_namespace&.organization_id,
            ai_feature_name: :duo_agent_platform,
            feature_setting: feature_setting,
            extra_claims: {
              tool_access_policies: tool_access_policies.to_json,
              gitlab_paid_credit_models_allowed:
                !::Ai::ModelSelection::CreditGate.new(governing_namespace).applies?,
              # GenerateToken copies this onto the token it mints.
              binds_workflow: true
            },
            bearer_token: bearer_token
          )
            .merge({ 'X-Gitlab-Client-Type' => 'gitlab-rails' })
            .except('Content-Type') # gRPC is not "application/json"
            .transform_keys(&:downcase)
        end

        # Carries no first_party_tools on purpose, which fails closed: DWS treats a client tool
        # of a first-party name as client-injected and prompts. A first-party deny still
        # arrives through denied_tools.
        def tool_access_policies
          policies = { allow: @pre_approved_tools, ask: @ask_tools, deny: @denied_tools }
          policies[:ceiling] = true if @ceiling
          policies
        end

        def channel_credentials
          if @secure
            GRPC::Core::ChannelCredentials.new(::Gitlab::X509::Certificate.ca_certs_bundle)
          else
            :this_channel_is_insecure
          end
        end
      end
    end
  end
end
