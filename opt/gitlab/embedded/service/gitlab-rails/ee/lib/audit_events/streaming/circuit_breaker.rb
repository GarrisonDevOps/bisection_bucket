# frozen_string_literal: true

# Per-destination circuit breaker for audit event streaming.
#
# Tracks failures originating from external services / user-supplied
# configuration (the same class of errors that BaseStreamer#log_only_error?
# considers non-actionable). When a destination accumulates more than
# FAILURE_THRESHOLD such failures inside FAILURE_WINDOW, the breaker is
# tripped and the destination is skipped for OPEN_DURATION.
#
# State is stored in Gitlab::Redis::SharedState - there is no DB column.
# This matches the pattern used by Gitlab::CircuitBreaker (Circuitbox) and
# Gitlab::GitalyClient::CircuitBreaker, and avoids hot-path DB writes for
# what is by definition a failure protection mechanism.
module AuditEvents
  module Streaming
    module CircuitBreaker
      FAILURE_THRESHOLD = 25
      FAILURE_WINDOW = 5.minutes
      OPEN_DURATION = 5.minutes

      OPEN_KEY_FORMAT = 'audit_events:streaming:circuit:{%<scope>s}:open:%<id>s'
      FAILURE_KEY_FORMAT = 'audit_events:streaming:circuit:{%<scope>s}:failures:%<id>s'

      class << self
        def open?(destination)
          return false unless trackable?(destination)

          with_redis { |r| r.exists?(open_key(destination)) } # rubocop:disable CodeReuse/ActiveRecord -- Redis method, not ActiveRecord
        rescue ::Redis::BaseError, ::RedisClient::Error => e
          ::Gitlab::ErrorTracking.log_exception(e)
          false
        end

        def reject_open(destinations, delivery_mode:, event_count:)
          return destinations if destinations.empty?

          trackable, untrackable = destinations.partition { |d| trackable?(d) }
          return destinations if trackable.empty?

          open_flags = with_redis { |r| r.mget(*trackable.map { |d| open_key(d) }) }
          open, closed = trackable.zip(open_flags).partition { |_, flag| flag.present? }
          open.map(&:first).each { |destination| record_skipped(destination, delivery_mode, event_count) }

          untrackable + closed.map(&:first)
        rescue ::Redis::BaseError, ::RedisClient::Error => e
          ::Gitlab::ErrorTracking.log_exception(e)
          destinations
        end

        def record_failure(destination)
          return unless trackable?(destination)

          key = failure_key(destination)
          count = with_redis do |r|
            r.multi do |m|
              m.incr(key)
              m.expire(key, FAILURE_WINDOW.to_i)
            end.first
          end

          trip!(destination) if count && count >= FAILURE_THRESHOLD
        rescue ::Redis::BaseError, ::RedisClient::Error => e
          ::Gitlab::ErrorTracking.log_exception(e)
        end

        def record_success(destination)
          return unless trackable?(destination)

          with_redis { |r| r.del(failure_key(destination)) }
        rescue ::Redis::BaseError, ::RedisClient::Error => e
          ::Gitlab::ErrorTracking.log_exception(e)
        end

        private

        def trip!(destination)
          set_result = with_redis do |r|
            r.set(open_key(destination), '1', ex: OPEN_DURATION.to_i, nx: true)
          end

          notify_tripped(destination) if set_result
        end

        def notify_tripped(destination)
          ::Gitlab::AppLogger.warn(
            message: 'Audit event streaming destination disabled by circuit breaker',
            destination_id: destination.id,
            destination_name: destination.name,
            destination_category: destination.category,
            destination_scope: scope_for(destination),
            disabled_for_seconds: OPEN_DURATION.to_i
          )

          AuditEventStreamingWorker::CIRCUIT_BREAKER_COUNTER.increment(
            scope: scope_for(destination),
            category: destination.category.to_s
          )
        rescue StandardError => e
          ::Gitlab::ErrorTracking.log_exception(e)
        end

        def record_skipped(destination, delivery_mode, event_count)
          ::Gitlab::Metrics::AuditEventStreamingSlis.record_deliveries_skipped(
            scope: scope_for(destination),
            category: destination.category.to_s,
            delivery_mode: delivery_mode.to_s,
            count: event_count
          )
        rescue StandardError => e
          ::Gitlab::ErrorTracking.track_exception(e)
        end

        def trackable?(destination)
          destination.id.present?
        end

        def open_key(destination)
          format(OPEN_KEY_FORMAT, scope: scope_for(destination), id: destination.id)
        end

        def failure_key(destination)
          format(FAILURE_KEY_FORMAT, scope: scope_for(destination), id: destination.id)
        end

        def scope_for(destination)
          instance_scope?(destination) ? 'instance' : 'group'
        end

        def instance_scope?(destination)
          !destination.respond_to?(:group)
        end

        def with_redis(&block)
          ::Gitlab::Redis::SharedState.with(&block) # rubocop:disable CodeReuse/ActiveRecord -- Redis connection pool, not ActiveRecord
        end
      end
    end
  end
end
