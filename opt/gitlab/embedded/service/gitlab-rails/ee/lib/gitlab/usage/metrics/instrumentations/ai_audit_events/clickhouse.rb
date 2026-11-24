# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        module AiAuditEvents
          # Only ClickHouse-analytics instances write AI audit events to ClickHouse; the gate skips the query elsewhere.
          # A concern, not a parent class: the available? block lives in a class ivar that subclasses do not inherit.
          module Clickhouse
            extend ActiveSupport::Concern

            included do
              available? { ::Gitlab::ClickHouse.globally_enabled_for_analytics? }
            end

            def value
              # Re-check the available? gate: Service Ping validation specs force
              # every metric available, bypassing it.
              return disabled_value unless ::Gitlab::ClickHouse.globally_enabled_for_analytics?

              alt_usage_data(fallback: self.class.fallback) { clickhouse_value }
            end

            private

            def clickhouse_value
              raise NotImplementedError
            end

            def disabled_value
              self.class.fallback
            end

            def time_constraint
              return '' if time_frame == 'all'
              return ' WHERE created_at >= now() - INTERVAL 28 DAY' if time_frame == '28d'

              raise ArgumentError, "Unsupported time_frame: #{time_frame}"
            end
          end
        end
      end
    end
  end
end
