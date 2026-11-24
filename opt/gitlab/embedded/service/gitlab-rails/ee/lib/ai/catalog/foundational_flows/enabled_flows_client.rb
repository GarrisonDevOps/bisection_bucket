# frozen_string_literal: true

module Ai
  module Catalog
    module FoundationalFlows
      # The flow ids GitLab enabled for this instance, from the GitLab-hosted AI gateway.
      # On a failed lookup it returns the last good answer, or no flows if there is none.
      # Only flows the Duo Workflow Service gates (ai-assist GATED_FLOWS) can be listed.
      class EnabledFlowsClient
        TIMEOUT = 2.seconds
        CACHE_KEY = 'ai_catalog_gitlab_enabled_flows'
        CACHE_EXPIRATION = 30.minutes
        FAILURE_CACHE_EXPIRATION = 5.minutes
        RACE_CONDITION_TTL = 10.seconds
        LAST_GOOD_CACHE_KEY = 'ai_catalog_gitlab_enabled_flows_last_good'
        LAST_GOOD_CACHE_EXPIRATION = 1.day
        ENDPOINT_PATH = '/v1/flows/enabled'

        def self.enabled?(flow_config_id)
          new.execute.include?(flow_config_id.to_s)
        end

        def execute
          return [] if ::License.current&.offline_cloud_license?

          ::Gitlab::SafeRequestStore.fetch(CACHE_KEY) { cached_enabled_flows }
        end

        private

        # On expiry one process refreshes the answer while the others briefly keep serving the old one.
        def cached_enabled_flows
          Rails.cache.fetch(
            CACHE_KEY,
            expires_in: CACHE_EXPIRATION,
            race_condition_ttl: RACE_CONDITION_TTL
          ) do |_key, options|
            flows = fetch_enabled_flows

            if flows.nil?
              options.expires_in = FAILURE_CACHE_EXPIRATION
              Rails.cache.read(LAST_GOOD_CACHE_KEY) || []
            else
              Rails.cache.write(LAST_GOOD_CACHE_KEY, flows, expires_in: LAST_GOOD_CACHE_EXPIRATION)
              flows
            end
          end
        end

        # The enabled flow ids, or nil when the lookup failed.
        def fetch_enabled_flows
          response = ::Gitlab::HTTP.get(endpoint, headers: headers, timeout: TIMEOUT, allow_local_requests: true)

          unless response.success?
            log_error("Received error #{response.code} from AI gateway when fetching enabled flows")
            return
          end

          body = response.parsed_response
          flows = body['enabled_flows'] if body.is_a?(Hash)
          return flows.grep(String) if flows.is_a?(Array)

          log_error('Unexpected response from AI gateway when fetching enabled flows')
          nil
        rescue StandardError => e
          log_error("Error fetching enabled flows: #{e.message}", exception: e.class.name)
          nil
        end

        # GitLab decides which flows are enabled, so this always asks the GitLab-hosted AI gateway.
        def endpoint
          "#{::Gitlab::AiGateway.cloud_connector_url}#{ENDPOINT_PATH}"
        end

        # An instance-level call: the instance's Cloud Connector token, no user.
        def headers
          ::Gitlab::AiGateway.headers(user: nil, unit_primitive_name: :duo_agent_platform)
        end

        def log_error(message, **extra)
          ::Gitlab::AppLogger.error(message: message, ai_component: 'foundational_flows', **extra)
        end
      end
    end
  end
end
