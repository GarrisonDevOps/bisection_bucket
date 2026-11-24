# frozen_string_literal: true

module Gitlab
  module Llm
    module AiGateway
      class CodeSuggestionsClient
        include ::Gitlab::Utils::StrongMemoize
        include Gitlab::Llm::Concerns::Logger

        COMPLETION_CHECK_TIMEOUT = 3.seconds
        DEFAULT_TIMEOUT = 30.seconds
        TOKEN_TIMEOUT = 3.seconds
        TOKEN_CACHE_EXPIRY_MARGIN = 5.minutes

        AiGatewayError = Class.new(StandardError)

        def initialize(user, project: nil)
          @user = user
          @project = project
        end

        def test_completion
          response = call_endpoint task.endpoint, task.body

          return "AI Gateway returned code #{response.code}: #{response.body}" unless response.code == 200
          return "Response doesn't contain a completion" unless choice?(response)

          nil
        rescue StandardError => err
          Gitlab::ErrorTracking.track_exception(err)
          err.message
        end

        def call_endpoint(endpoint, body)
          Gitlab::HTTP.post(
            endpoint,
            headers: ai_gateway_headers,
            body: body,
            timeout: COMPLETION_CHECK_TIMEOUT,
            allow_local_requests: true
          )
        end

        def direct_access_token
          cached = read_cached_direct_access_token
          return cached if cached

          mint_direct_access_token.tap { |result| cache_direct_access_token(result) }
        end

        private

        attr_reader :user, :project

        def mint_direct_access_token
          log_info(message: 'Creating user access token',
            event_name: 'user_token_created',
            ai_component: 'code_suggestion'
          )

          token_timeout = TOKEN_TIMEOUT

          if missing_required_feature_setting?
            return error('No Code Completion model provided',
              {
                error: 'Please, assign a model to the ' \
                  '"Code completion" feature settings in your duo settings',
                response_code: 400
              })
          end

          response = Gitlab::HTTP.post(
            Gitlab::AiGateway.access_token_url(code_completions_feature_setting),
            headers: ai_gateway_headers(feature_setting: code_completions_feature_setting),
            body: nil,
            timeout: token_timeout,
            allow_local_requests: true,
            stream_body: false
          )

          raise AiGatewayError, 'Token creation failed' unless response.success?
          raise AiGatewayError, 'Token is missing in response' unless response['token'].present?

          success(token: response['token'], expires_at: response['expires_at'])
        rescue AiGatewayError => err
          error_context = {}.tap do |h|
            next if response.nil?

            h[:response_code] = response.code
            if response.parsed_response.is_a?(String)
              h[:detail] = response.parsed_response
            elsif response.parsed_response.respond_to?(:dig)
              h.merge!(response.parsed_response.slice('detail', 'error', 'error_code',
                'message').transform_keys(&:to_sym))
            end
          end
          Gitlab::ErrorTracking.track_exception(err, error_context)
          error(err.message, error_context)
        end

        def read_cached_direct_access_token
          cached = Rails.cache.read(direct_access_token_cache_key)
          return unless cached

          cached.merge(token: Authn::TokenField::EncryptionHelper.decrypt_token(cached[:token]))
        rescue OpenSSL::Cipher::CipherError
          nil
        end

        def cache_direct_access_token(result)
          return unless result[:status] == :success

          ttl = result[:expires_at].to_i - Time.current.to_i - TOKEN_CACHE_EXPIRY_MARGIN.to_i
          return unless ttl > 0

          encrypted = result.merge(token: Authn::TokenField::EncryptionHelper.encrypt_token(result[:token]))
          Rails.cache.write(direct_access_token_cache_key, encrypted, expires_in: ttl.seconds)
        end

        def direct_access_token_cache_key
          [
            'code_suggestions_direct_access_token',
            {
              user: user.id,
              project: project&.id,
              governing_namespace: governing_namespace&.id,
              feature_setting: code_completions_feature_setting&.cache_key_with_version,
              url: Gitlab::AiGateway.access_token_url(code_completions_feature_setting)
            }
          ]
        end
        strong_memoize_attr :direct_access_token_cache_key

        # The AI Gateway needs the root namespace for the usage billing
        # check on GitLab.com. If the namespace is missing, the check
        # denies the request. See
        # https://gitlab.com/gitlab-org/gitlab/-/work_items/605887
        def ai_gateway_headers(feature_setting: nil)
          Gitlab::AiGateway.headers(
            user: user,
            unit_primitive_name: task.unit_primitive_name,
            ai_feature_name: task.feature_name,
            namespace_id: project&.namespace_id,
            project_id: project&.id,
            governing_namespace_id: governing_namespace&.id,
            organization_id: governing_namespace&.organization_id,
            feature_setting: feature_setting
          )
        end

        def governing_namespace
          ::Ai::UserAuthorizer.for(user).governing_namespace(project)
        end
        strong_memoize_attr :governing_namespace

        def code_completions_feature_setting
          ::Ai::FeatureSetting.find_by_feature(:code_completions)
        end
        strong_memoize_attr :code_completions_feature_setting

        # A pinned model is required only when the token request goes to
        # a self-hosted AI Gateway. A vendored setting routes the token
        # request to the cloud connector, even when a self-hosted AI
        # Gateway is configured (hybrid setup). See
        # https://gitlab.com/gitlab-org/gitlab/-/work_items/605887
        def missing_required_feature_setting?
          return false if code_completions_feature_setting&.vendored?

          Gitlab::AiGateway.has_self_hosted_ai_gateway? && !code_completions_feature_setting&.self_hosted?
        end

        def error(message, context)
          {
            message: message,
            status: :error,
            context: context
          }
        end

        def success(pass_back = {})
          pass_back[:status] = :success
          pass_back
        end

        def choice?(response)
          response['choices']&.first&.dig('text').present?
        end

        def task
          inputs = {
            prompt_version: 1,
            current_file: {
              file_name: 'test.rb',
              content_above_cursor: 'def hello_world'
            }
          }

          CodeSuggestions::Tasks::CodeCompletion.new(
            params: inputs,
            unsafe_passthrough_params: inputs,
            current_user: user
          )
        end
        strong_memoize_attr :task
      end
    end
  end
end
