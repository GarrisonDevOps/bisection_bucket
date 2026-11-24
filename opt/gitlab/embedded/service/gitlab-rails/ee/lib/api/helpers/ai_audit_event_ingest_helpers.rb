# frozen_string_literal: true

module API
  module Helpers
    module AiAuditEventIngestHelpers
      # Always counts the request, so the limit can be checked against real traffic before it rejects
      # anything. Over the limit, it only answers 429 while enforcement is on for the top-level namespace.
      def check_ai_audit_event_ingest_limit!(key, scope:, top_level_namespace:, **options)
        if Feature.enabled?(:enforce_ai_audit_event_ingest_limits, top_level_namespace)
          check_rate_limit!(key, scope: scope, **options)
        else
          ::Gitlab::ApplicationRateLimiter.throttled_request?(request, current_user, key, scope: scope, **options)
        end
      end
    end
  end
end
