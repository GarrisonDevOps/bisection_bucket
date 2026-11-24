# frozen_string_literal: true

module Analytics
  module Orbit
    module Trial
      TRIAL_TYPE = :orbit
      CDOT_UNAVAILABLE_KEY = :orbit_trial_cdot_unavailable
      REFUSING_STATUSES = [401, 429].freeze
      private_constant :CDOT_UNAVAILABLE_KEY, :REFUSING_STATUSES

      # Status reads run on page loads, so a stalled CDot must not stall the page.
      STATUS_HTTP_TIMEOUT_SECONDS = 2.0

      def self.status_for(group, timeout: STATUS_HTTP_TIMEOUT_SECONDS)
        ::Gitlab::SubscriptionPortal::Client.product_trial(
          trial_type: TRIAL_TYPE, namespace_id: group.id, timeout: timeout
        )
      end

      def self.status_for_instance(timeout: STATUS_HTTP_TIMEOUT_SECONDS)
        ::Gitlab::SubscriptionPortal::Client.product_trial(
          trial_type: TRIAL_TYPE, instance_id: ::Gitlab::CurrentSettings.uuid, timeout: timeout
        )
      end

      def self.request_status_for(group)
        request_status(identity: { namespace_id: group.id }, gl_namespace_id: group.id)
      end

      def self.request_instance_status
        request_status(identity: { instance_id: ::Gitlab::CurrentSettings.uuid }, gl_namespace_id: nil)
      end

      def self.request_status(identity:, gl_namespace_id:)
        return :unavailable if ::Gitlab::SafeRequestStore[CDOT_UNAVAILABLE_KEY]

        ::Gitlab::SubscriptionPortal::Client.product_trial(
          trial_type: TRIAL_TYPE, timeout: STATUS_HTTP_TIMEOUT_SECONDS, **identity
        )
      rescue ::Gitlab::SubscriptionPortal::ProductTrialResponse::UnavailableError => e
        ::Gitlab::SafeRequestStore[CDOT_UNAVAILABLE_KEY] = true
        ::Gitlab::ErrorTracking.track_exception(e, gl_namespace_id: gl_namespace_id)
        :unavailable
      rescue ::Gitlab::SubscriptionPortal::ProductTrialResponse::Error => e
        ::Gitlab::SafeRequestStore[CDOT_UNAVAILABLE_KEY] = true if REFUSING_STATUSES.include?(e.cdot_status)
        ::Gitlab::ErrorTracking.track_exception(e, gl_namespace_id: gl_namespace_id)
        :unavailable
      end
      private_class_method :request_status
    end
  end
end
