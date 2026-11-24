# frozen_string_literal: true

module Mutations
  module Ai
    module Compliance
      module Anthropic
        # Shared by the mutations that send a Compliance Access Key to Anthropic, so their limits cannot drift apart.
        module VerifiesAccessKey
          extend ActiveSupport::Concern

          include Mutations::ResolvesGroup

          private

          def find_object(group_path:)
            resolve_group(full_path: group_path)
          end

          # Every attempt can reach Anthropic, so without a limit GitLab could be used to test
          # stolen keys. The user limit stops one actor spreading attempts across groups.
          def rate_limited?(group)
            ::Gitlab::ApplicationRateLimiter.throttled?(
              :anthropic_compliance_key_verification_by_group, scope: { group: group }
            ) || ::Gitlab::ApplicationRateLimiter.throttled?(
              :anthropic_compliance_key_verification_by_user, scope: { user: current_user }
            )
          end

          def rate_limited_response(integration: nil)
            error_response(
              s_('AiGovernance|Too many Compliance Access Key verification attempts. Try again later.'),
              :rate_limited,
              integration: integration
            )
          end

          # Update mutations pass the unchanged integration so clients see its current state.
          def error_response(message, reason, integration: nil)
            { anthropic_compliance_integration: integration, errors: [message], error_reason: reason }
          end
        end
      end
    end
  end
end
