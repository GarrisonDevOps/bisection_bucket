# frozen_string_literal: true

module Security
  module ScanProfiles
    # Contention on a namespace lease is expected, so the Sidekiq retry it triggers is not sent to Sentry.
    LeaseTakenError = Class.new(::Gitlab::SidekiqMiddleware::RetryError)

    def self.update_lease_key(namespace_id)
      "update_scan_profile:namespace:#{namespace_id}"
    end
  end
end
