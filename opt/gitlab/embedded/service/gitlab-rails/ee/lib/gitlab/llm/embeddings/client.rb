# frozen_string_literal: true

module Gitlab
  module Llm
    module Embeddings
      class Client
        include ::Gitlab::Llm::Concerns::ExponentialBackoff
        include ::Gitlab::Llm::Concerns::Logger
        include Gitlab::Utils::StrongMemoize

        # Vertex AI's past service degradation exceeded the 20-second Gitlab::HTTP default.
        # Only indexing (a background job) gets 30 seconds; search keeps the default,
        # since it runs inside a live web request.
        INDEX_READ_TIMEOUT = 30.seconds

        def initialize(user: nil, root_namespace_id: nil)
          @user = user
          @root_namespace_id = root_namespace_id
        end

        def code_embeddings(contents:, model_definition:, search: false, dimensions: nil)
          operation = search ? "search" : "index"
          type = "code_embeddings/#{operation}"

          request(
            type: type,
            model_definition: model_definition,
            contents: contents,
            read_timeout: search ? nil : INDEX_READ_TIMEOUT,
            dimensions: dimensions
          )
        end

        private

        attr_reader :user, :root_namespace_id

        def request(type:, model_definition:, contents:, read_timeout: nil, dimensions: nil)
          url = "#{model_definition.aigw_base_url}/v1/embeddings/#{type}"

          # this payload matches the payload defined in the AIGW file
          # ai_gateway/api/v1/embeddings/typing.py (EmbeddingsRequest)
          payload = {
            model_metadata: model_definition.model_params,
            litellm_drop_params: model_definition.litellm_drop_params?,
            contents: contents
          }
          payload[:dimensions] = dimensions unless dimensions.nil?

          log_request(type: type, model_definition: model_definition, url: url) do
            response = retry_with_exponential_backoff do
              Gitlab::HTTP.post(url,
                {
                  headers: headers(model_definition),
                  body: payload.to_json,
                  read_timeout: read_timeout
                }.compact
              )
            end

            Gitlab::Llm::Embeddings::Response.new(response)
          end
        end

        def headers(model_definition)
          Gitlab::AiGateway.headers(
            user: user,
            unit_primitive_name: model_definition.unit_primitive,
            ai_feature_name: model_definition.feature_name,
            organization_id: root_namespace&.organization_id,
            governing_namespace_id: request_root_namespace_id
          ).merge(
            "Accept" => "application/json"
          )
        end

        def log_request(type:, model_definition:, url:)
          ai_component = ai_component_for_logging(type)

          log_info(
            message: 'Performing embeddings request',
            event_name: 'performing_request',
            ai_component: ai_component,
            unit_primitive: model_definition.unit_primitive,
            url: url,
            user_id: user&.id,
            root_namespace_id: request_root_namespace_id,
            params: { model_metadata: model_definition.model_params }.to_json
          )

          response = yield

          response_log_params = {
            message: 'Received embeddings response',
            event_name: 'response_received',
            ai_component: ai_component,
            unit_primitive: model_definition.unit_primitive,
            url: url
          }

          response_log_params[:error] = response.error.truncate(100) if response.error.present?

          log_info(**response_log_params)

          response
        end

        def ai_component_for_logging(type)
          type.tr('/', '_')
        end

        def root_namespace
          user && ::Ai::UserAuthorizer.for(user).governing_namespace unless root_namespace_id
        end
        strong_memoize_attr :root_namespace

        def request_root_namespace_id
          root_namespace_id || root_namespace&.id
        end
        strong_memoize_attr :request_root_namespace_id
      end
    end
  end
end
