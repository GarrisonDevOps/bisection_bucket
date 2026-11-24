# frozen_string_literal: true

module Labkit
  module Tracing
    module Rails
      module ActiveRecord
        # For more information on the payloads: https://guides.rubyonrails.org/active_support_instrumentation.html
        class SqlInstrumenter < Labkit::Tracing::AbstractInstrumenter
          OPERATION_NAME_PREFIX = "active_record:"
          DEFAULT_OPERATION_NAME = "sqlquery"

          def span_name(payload)
            OPERATION_NAME_PREFIX + (payload[:name].presence || DEFAULT_OPERATION_NAME)
          end

          def tags(payload)
            if Labkit::Tracing.sampled? && payload[:sql]
              sql = Labkit::Logging::Sanitizer.sanitize_sql(payload[:sql])
              fingerprint = Labkit::Logging::Sanitizer.sql_fingerprint(sql)
            end

            tags = {
              "component" => COMPONENT_TAG,
              "span.kind" => "client",
              "db.type" => "sql",
              "db.cached" => payload[:cached] || false,
            }

            # OpenTelemetry rejects nil attributes, so only add statement fields
            # when ActiveRecord supplies SQL (schema events may omit it).
            tags["db.statement"] = sql if sql
            tags["db.statement_fingerprint"] = fingerprint if fingerprint
            tags["db.connection_id"] = payload[:connection_id] if payload[:connection_id]

            tags
          end
        end
      end
    end
  end
end
