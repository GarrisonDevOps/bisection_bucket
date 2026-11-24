# frozen_string_literal: true

module Gitlab
  module Ci
    module JobTelemetry
      # Custom OpenTelemetry IdGenerator that lets callers emit spans with
      # deterministic span_ids (primed via #with_span_id) instead of random ones.
      # Falls back to random IDs when no span_id is primed.
      #
      # Thread-safe: the primed value is stored in Thread.current.
      class DeterministicIdGenerator
        PRIMED_KEY = :gitlab_ci_telemetry_primed_span_id

        def with_span_id(hex_span_id)
          previous = Thread.current[PRIMED_KEY]
          Thread.current[PRIMED_KEY] = [hex_span_id].pack('H*')
          yield
        ensure
          Thread.current[PRIMED_KEY] = previous
        end

        def generate_span_id
          primed = Thread.current[PRIMED_KEY]
          Thread.current[PRIMED_KEY] = nil if primed

          primed || ::OpenTelemetry::Trace.generate_span_id
        end

        def generate_trace_id
          ::OpenTelemetry::Trace.generate_trace_id
        end
      end
    end
  end
end
