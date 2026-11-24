# frozen_string_literal: true

module EE
  module Onboarding
    module FeatureLibrary
      module FeatureMatchService
        extend ::Gitlab::Utils::Override
        include ::Gitlab::InternalEventsTracking

        SEARCH_RESOLUTION_EVENT = 'resolve_feature_discovery_search'

        override :execute
        def execute
          with_search_tracking { super }
        end

        private

        def with_search_tracking
          start = ::Gitlab::Metrics::System.monotonic_time
          result = yield
          duration_ms = ((::Gitlab::Metrics::System.monotonic_time - start) * 1000).round
          track_search_resolution(label: tracking_label, duration_ms: duration_ms)

          result
        end

        def track_search_resolution(label:, duration_ms:)
          return unless user
          return if label.blank? # matching never ran

          track_internal_event(
            SEARCH_RESOLUTION_EVENT,
            user: user,
            project: (resource if panel == 'project'),
            namespace: (resource if panel == 'group'),
            additional_properties: {
              label: label,
              value: duration_ms
            }
          )
        end
      end
    end
  end
end
