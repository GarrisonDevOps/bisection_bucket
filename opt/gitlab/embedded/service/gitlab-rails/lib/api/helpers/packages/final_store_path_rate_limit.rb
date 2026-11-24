# frozen_string_literal: true

module API
  module Helpers
    module Packages
      module FinalStorePathRateLimit
        RATE_LIMIT_KEY = :package_final_store_path_authorize

        # Calls throttled? directly: check_rate_limit! honors the throttle bypass
        # header, which must not skip this cap on pending direct upload entries.
        def check_final_store_path_authorize_rate_limit!
          actor = current_user
          scope = actor.is_a?(::DeployToken) ? { deploy_token: actor } : { user: actor }

          return unless ::Gitlab::ApplicationRateLimiter.throttled?(RATE_LIMIT_KEY, scope: scope)

          too_many_requests!(retry_after: ::Gitlab::ApplicationRateLimiter.period_for(RATE_LIMIT_KEY))
        end
      end
    end
  end
end
