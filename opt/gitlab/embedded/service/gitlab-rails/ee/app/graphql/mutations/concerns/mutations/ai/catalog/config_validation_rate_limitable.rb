# frozen_string_literal: true

module Mutations
  module Ai
    module Catalog
      # Rate limits the mutations that save an agent, flow, third-party flow or
      # trigger, and version restore. All of them share one counter per user.
      module ConfigValidationRateLimitable
        extend ActiveSupport::Concern
        include ::Mutations::Ai::Catalog::RateLimitable

        CONFIG_VALIDATION_RATE_LIMIT_KEY = :ai_catalog_config_validation

        private

        def config_validation_rate_limited?
          return false unless Feature.enabled?(:ai_catalog_config_validation_rate_limit, current_user)

          rate_limited?(CONFIG_VALIDATION_RATE_LIMIT_KEY, scope: { user: current_user })
        end

        def config_validation_rate_limited_message
          s_('AICatalog|You have saved agents, flows, or triggers too many times. Try again in a minute.')
        end
      end
    end
  end
end
