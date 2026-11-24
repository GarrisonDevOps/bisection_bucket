# frozen_string_literal: true

module GitlabSubscriptions
  module Trials
    module PendingTrialMarker
      CACHE_TTL = 5.minutes

      def self.set(namespace_id)
        Rails.cache.write(cache_key(namespace_id), true, expires_in: CACHE_TTL)
      end

      def self.active?(namespace_id)
        Rails.cache.read(cache_key(namespace_id)).present?
      end

      def self.cache_key(namespace_id)
        "gitlab_subscriptions:trials:pending_trial_marker:#{namespace_id}"
      end
      private_class_method :cache_key
    end
  end
end
