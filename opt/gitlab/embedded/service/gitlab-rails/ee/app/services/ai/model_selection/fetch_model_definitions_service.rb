# frozen_string_literal: true

module Ai
  module ModelSelection
    class FetchModelDefinitionsService
      include ::Gitlab::Llm::Concerns::Logger

      FetchError = Class.new(StandardError)

      DEFAULT_TIMEOUT = 5.seconds
      RESPONSE_CACHE_EXPIRATION = 30.minutes
      RACE_CONDITION_TTL = 1.minute
      RESPONSE_CACHE_NAME = 'ai_offered_model_definitions'

      def initialize(user = nil)
        @user = user
      end

      def execute
        return ServiceResponse.success(payload: nil) if ::License.current&.offline_cloud_license?

        return request_model_definitions if local_development?

        fetch_serving_stale_on_error
      rescue StandardError => e
        unexpected_error_response(e)
      end

      private

      attr_reader :user

      def fetch_serving_stale_on_error
        Gitlab::SafeRequestStore.fetch("#{self.class.name}:#{cache_key}") do
          payload = Rails.cache.fetch(
            cache_key,
            expires_in: RESPONSE_CACHE_EXPIRATION,
            race_condition_ttl: RACE_CONDITION_TTL
          ) do
            response = request_model_definitions
            raise FetchError, response.message unless response.success?

            response.payload
          end

          ServiceResponse.success(payload: payload)
        rescue FetchError => e
          cached_response_or(ServiceResponse.error(message: e.message))
        rescue StandardError => e
          cached_response_or(unexpected_error_response(e))
        end
      end

      def cached_response_or(error_response)
        cached_model_definitions = Rails.cache.read(cache_key)
        return error_response if cached_model_definitions.nil?

        ServiceResponse.success(payload: cached_model_definitions)
      end

      def request_model_definitions
        response = call_endpoint

        if response.success?
          ServiceResponse.success(payload: response.parsed_response)
        else
          parsed_response = response.parsed_response
          error_message = "Received error #{response.code} from AI gateway when fetching model definitions"

          log_error(message: error_message,
            event_name: 'error_response_received',
            ai_component: 'abstraction_layer',
            response_from_llm: parsed_response)

          ServiceResponse.error(message: error_message)
        end
      end

      def unexpected_error_response(error)
        Gitlab::AppLogger.error(
          message: "Error fetching model definitions: #{error.message}",
          exception_class: error.class.name,
          ai_component: 'model_selection'
        )
        ServiceResponse.error(message: "Failed to fetch model definitions")
      end

      def call_endpoint
        Gitlab::AiGateway.push_feature_flag(:ai_model_release, user)

        Gitlab::HTTP.get(
          endpoint,
          headers: Gitlab::AiGateway.public_headers(
            user: user,
            unit_primitive_name: :code_suggestions,
            ai_feature_name: :code_suggestions
          ),
          timeout: DEFAULT_TIMEOUT,
          allow_local_requests: true
        )
      end

      # AI Gateway returns different definitions depending on ai_model_release, so cache each variant separately.
      def cache_key
        return RESPONSE_CACHE_NAME unless Feature.enabled?(:ai_model_release, user)

        "#{RESPONSE_CACHE_NAME}:ai_model_release"
      end

      def endpoint
        # GitLab Model selection data should always come from cloud connected, never from local AIGW
        base_url = if local_development?
                     Gitlab::AiGateway.url
                   else
                     Gitlab::AiGateway.cloud_connector_url
                   end

        endpoint_route = 'models%2Fdefinitions'

        "#{base_url}/v1/#{endpoint_route}"
      end

      def local_development?
        ::Gitlab::Utils.to_boolean(ENV['FETCH_MODEL_SELECTION_DATA_FROM_LOCAL'], default: false)
      end
    end
  end
end
