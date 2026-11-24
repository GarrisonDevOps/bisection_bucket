# frozen_string_literal: true

module Ai
  class PostgresqlUsageEventsFinder < BaseUsageEventsFinder
    def execute
      scope = ::Ai::UsageEvent.in_timeframe(from..to).sort_by_timestamp_id
      scope = scope.with_events(events) if events.present?
      scope = scope.with_users(users) if users.present?
      scope = scope.for_namespace_hierarchy(namespace) if namespace
      scope
    end
  end
end
