# frozen_string_literal: true

module Ai
  module Compliance
    module Anthropic
      # Replaces the Compliance Access Key of an integration, or turns it on or off.
      class UpdateIntegrationService
        # @param integration [Ai::Compliance::Anthropic::Integration]
        # @param current_user [User]
        # @param api_key [String, nil] new key; nil keeps the stored one
        # @param enabled [Boolean, nil] true or false turns the integration on or off; nil leaves it
        def initialize(integration, current_user:, api_key: nil, enabled: nil)
          @integration = integration
          @current_user = current_user
          @api_key = api_key
          @enabled = enabled
        end

        # True when execute sends a key to Anthropic, so callers can rate limit before calling it.
        def verification_needed?
          return false if enabled == false

          !api_key.nil? || !integration.enabled
        end

        def execute
          return disable if enabled == false
          return success unless verification_needed?

          verify_and_store
        end

        private

        attr_reader :integration, :current_user, :api_key, :enabled

        def verify_and_store
          replaced = !api_key.nil?
          was_enabled = integration.enabled
          # A new key leaves an integration the owner turned off switched off. Turning it on
          # re-verifies the stored key: it may have been revoked while disabled.
          enable = !replaced || !owner_disabled?

          result = SetAccessKeyService.new(integration, api_key: api_key || integration.api_key, enable: enable).execute

          return error(result.message, result.reason) if result.error?

          audit('Replaced Anthropic Compliance Access Key') if replaced
          audit('Enabled Anthropic Compliance integration') if integration.enabled && !was_enabled

          success
        end

        # A nil disabled_reason records that an owner, not GitLab, turned the integration off.
        def disable
          return success if owner_disabled?

          unless integration.update(enabled: false, disabled_reason: nil)
            message = integration.errors.full_messages.to_sentence
            integration.restore_attributes(%i[enabled disabled_reason])

            return error(message, :invalid_integration)
          end

          audit('Disabled Anthropic Compliance integration')

          success
        end

        def owner_disabled?
          !integration.enabled && integration.disabled_reason.nil?
        end

        def success
          ServiceResponse.success(payload: { integration: integration })
        end

        def error(message, reason)
          ServiceResponse.error(message: message, reason: reason, payload: { integration: integration })
        end

        def audit(message)
          ::Gitlab::Audit::Auditor.audit(
            name: 'anthropic_compliance_integration_updated',
            author: current_user,
            scope: integration.namespace,
            target: integration.namespace,
            message: message
          )
        end
      end
    end
  end
end
