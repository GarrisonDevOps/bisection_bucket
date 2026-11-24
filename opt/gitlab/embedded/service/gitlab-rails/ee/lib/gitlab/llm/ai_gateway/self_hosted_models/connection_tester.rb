# frozen_string_literal: true

module Gitlab
  module Llm
    module AiGateway
      module SelfHostedModels
        class ConnectionTester
          ENDPOINT_PATH = '/v1/prompts/model_configuration%2Fcheck'
          UNIT_PRIMITIVE = :complete_code
          AI_FEATURE_NAME = :code_suggestions
          TIMEOUT = 15.seconds

          # AI Gateway provider name for each `Ai::SelfHostedModel` provider. Models served through an
          # OpenAI-compatible API are sent as `openai`; AI Gateway routes the others by the model identifier.
          PROVIDER_NAMES = {
            'api' => 'openai',
            'bedrock' => 'bedrock',
            'vertex_ai' => 'vertex_ai'
          }.freeze

          MockFeatureSetting = Struct.new(:self_hosted_model, :feature, :provider, :self_hosted?)

          def initialize(user, self_hosted_model)
            @user = user
            @self_hosted_model = self_hosted_model
          end

          def execute
            return 'No self-hosted model was provided' unless self_hosted_model

            response = post_connection_check

            return model_server_error(response) if response.code == 421

            return "AI Gateway returned code #{response.code}: #{error_detail(response)}" unless response.code == 200

            nil
          rescue *Gitlab::HTTP::HTTP_ERRORS => err
            Gitlab::ErrorTracking.track_exception(err)
            connection_error
          rescue StandardError => err
            Gitlab::ErrorTracking.track_exception(err)
            err.message
          end

          private

          attr_reader :user, :self_hosted_model

          def connection_error
            s_('AdminSelfHostedModels|AI Gateway could not connect to the model endpoint. Verify the model ' \
              'endpoint URL is correct and reachable from the AI Gateway, and that any firewall or proxy is ' \
              'not blocking the connection.')
          end

          def model_server_error(response)
            detail = ::Gitlab::Json.safe_parse(response.body)&.[]("detail")
            return 'The self-hosted model server returned an error' if detail.blank?

            identifier_suggestion(detail) || "The self-hosted model server returned code #{detail}"
          end

          def identifier_suggestion(detail)
            return unless model_not_found?(detail)

            IdentifierSuggester.new(self_hosted_model).suggestion_message
          end

          def model_not_found?(detail)
            detail.to_s.start_with?('404')
          end

          def post_connection_check
            Gitlab::HTTP.post(
              "#{Gitlab::AiGateway.url}#{ENDPOINT_PATH}",
              headers: headers,
              body: body,
              timeout: TIMEOUT,
              allow_local_requests: true
            )
          end

          def headers
            Gitlab::AiGateway.headers(
              user: user,
              unit_primitive_name: UNIT_PRIMITIVE,
              ai_feature_name: AI_FEATURE_NAME,
              organization_id: ::Ai::UserAuthorizer.for(user).governing_namespace&.organization_id,
              feature_setting: MockFeatureSetting.new(self_hosted_model, 'code_completions', 'self_hosted', true)
            )
          end

          def body
            ::Gitlab::Json.dump(
              stream: false,
              inputs: {},
              model_metadata: {
                name: self_hosted_model.model,
                endpoint: self_hosted_model.endpoint,
                api_key: self_hosted_model.api_token,
                provider: PROVIDER_NAMES.fetch(self_hosted_model.provider),
                identifier: self_hosted_model.identifier
              }.merge(self_hosted_model.iam_role_metadata)
            )
          end

          def error_detail(response)
            ::Gitlab::Json.safe_parse(response.body).dig("detail", 0, "msg")
          rescue StandardError
            'Unknown error. Make sure your self-hosted model is running ' \
              'and that your AI Gateway URL is configured correctly.'
          end
        end
      end
    end
  end
end
