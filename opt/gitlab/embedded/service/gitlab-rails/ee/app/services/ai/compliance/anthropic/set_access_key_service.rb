# frozen_string_literal: true

module Ai
  module Compliance
    module Anthropic
      # Verifies a Compliance Access Key against Anthropic before storing it, so a key
      # that cannot read transcripts is never saved as though it works.
      class SetAccessKeyService
        # Runs inside a web request, unlike every other Client caller. Client sleeps
        # between retries, so one attempt with a short timeout replaces its defaults.
        VALIDATION_TIMEOUT = 10.seconds
        VALIDATION_ATTEMPTS = 1

        # The smallest response that still proves the key can read local sessions.
        PROBE_LIMIT = 1

        STORED_ATTRIBUTES = %i[api_key enabled disabled_reason consecutive_failure_count last_error].freeze

        # enable: false stores a verified key but leaves the integration off.
        def initialize(integration, api_key:, enable: true)
          @integration = integration
          @enable = enable
          # A pasted trailing newline makes Net::HTTP raise on the header instead of
          # returning a response, and would be stored as part of the key.
          @api_key = api_key&.strip
        end

        def execute
          return blank_key_error if api_key.blank?
          # Checked first so a key we would refuse to store is never sent to Anthropic.
          return invalid_integration_error unless valid_with_key?

          probe

          store(enabled: enable)
        rescue Client::LocalSessionsUnavailableError
          # The key authenticates; local sessions are switched off for the Claude
          # organization. Store it so the owner does not re-enter it once they enable them.
          # Keeps an owner's choice to turn the integration off, which a nil reason records.
          store(enabled: false, disabled_reason: enable ? :local_sessions_unavailable : nil)
        rescue Client::InvalidApiKeyError
          ServiceResponse.error(
            message:
              s_('AiGovernance|The Compliance Access Key was rejected by Anthropic. Check the key and its scopes.'),
            reason: :invalid_key
          )
        rescue Client::RateLimitedError
          # The request budget is shared across the Claude organization, so this says
          # nothing about the key.
          ServiceResponse.error(
            message: s_('AiGovernance|Anthropic rate limited the request. Try again shortly.'),
            reason: :rate_limited
          )
        rescue Client::Error => e
          ::Gitlab::ErrorTracking.track_exception(e, namespace_id: integration.namespace_id, request_id: e.request_id)

          ServiceResponse.error(
            message:
              s_('AiGovernance|Could not reach Anthropic to verify the Compliance Access Key. Try again shortly.'),
            reason: :verification_failed
          )
        end

        private

        attr_reader :integration, :api_key, :enable

        def blank_key_error
          ServiceResponse.error(message: s_('AiGovernance|A Compliance Access Key is required'), reason: :blank_key)
        end

        def invalid_integration_error
          ServiceResponse.error(message: integration.errors.full_messages.to_sentence, reason: :invalid_integration)
        end

        def valid_with_key?
          integration.api_key = api_key
          integration.valid?
        ensure
          integration.restore_attributes([:api_key])
        end

        def probe
          client.local_sessions(limit: PROBE_LIMIT)
        end

        def client
          Client.new(api_key: api_key, timeout: VALIDATION_TIMEOUT, max_attempts: VALIDATION_ATTEMPTS)
        end

        def store(enabled:, disabled_reason: nil)
          integration.api_key = api_key
          integration.enabled = enabled
          integration.disabled_reason = disabled_reason
          integration.consecutive_failure_count = 0
          integration.last_error = nil

          unless integration.save
            # Otherwise the caller's object keeps the unsaved key in memory.
            integration.restore_attributes(STORED_ATTRIBUTES)
            return invalid_integration_error
          end

          ServiceResponse.success(payload: { integration: integration })
        rescue ActiveRecord::RecordNotUnique
          # A concurrent create for the same group inserted after our uniqueness validation ran.
          integration.restore_attributes(STORED_ATTRIBUTES)
          integration.errors.add(:namespace_id, :taken)
          invalid_integration_error
        end
      end
    end
  end
end
