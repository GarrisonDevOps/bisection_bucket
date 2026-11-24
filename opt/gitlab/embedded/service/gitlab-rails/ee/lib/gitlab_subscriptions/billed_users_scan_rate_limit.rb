# frozen_string_literal: true

module GitlabSubscriptions
  module BilledUsersScanRateLimit
    RATE_LIMIT_KEYS = %i[
      billed_users_scan_per_minute
      billed_users_scan_per_hour
      billed_users_scan_per_day
    ].freeze

    def self.rate_limit_scope(user, namespace)
      { user: user, namespace: namespace.root_ancestor }
    end

    def check_billed_users_scan_rate_limit!(namespace)
      scope = BilledUsersScanRateLimit.rate_limit_scope(current_user, namespace)

      RATE_LIMIT_KEYS.each { |key| check_rate_limit!(key, scope: scope) }
    end
  end
end
