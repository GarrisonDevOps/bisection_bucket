# frozen_string_literal: true

module ClickHouse # rubocop:disable Gitlab/BoundedContexts -- existing module
  module MigrationSupport
    # Renews a lease, meant to run as a {Gitlab::BackgroundTask}, so the lease can
    # keep a short TTL and a killed process orphans it only briefly. Renewal stops
    # after max_duration so a hung but still alive process cannot hold it forever.
    class LeaseHeartbeat
      include ::Gitlab::Loggable

      # @param lease [Gitlab::ExclusiveLeaseHelpers::SleepingLock] an obtained lease
      # @param ttl [ActiveSupport::Duration] the lease TTL
      # @param interval [ActiveSupport::Duration] time between renewals, shorter than the TTL
      # @param max_duration [ActiveSupport::Duration] total time after which renewal stops
      def initialize(lease, ttl:, interval:, max_duration:)
        @lease = lease
        @ttl = ttl.to_f
        @interval = interval.to_f
        @renewed_at = monotonic_time
        @deadline = @renewed_at + max_duration.to_f
        @stop_signal = Queue.new
        @held = true
      end

      # Renews the lease every interval until stopped, the lease is lost, or max_duration passes.
      #
      # @return [void]
      def call
        while @held
          @stop_signal.pop(timeout: @interval)
          break if @stop_signal.closed?

          @held = monotonic_time < @deadline ? renew : lost!('renewal reached max_duration')
        end

        nil
      ensure
        @held = false
      end

      def stop
        @stop_signal.close

        nil
      end

      def held?
        @held
      end

      # @raise [ClickHouse::MigrationSupport::Errors::LockError] if the lease is no longer renewed
      def ensure_held!
        return if held?

        message = 'The ClickHouse migration lock is no longer held'
        message += ": #{@lost_reason}" if @lost_reason

        raise ClickHouse::MigrationSupport::Errors::LockError, message
      end

      private

      def renew
        return lost!('the lease expired or was taken over') unless @lease.renew

        @renewed_at = monotonic_time
        true
      rescue Redis::BaseError => e
        # A Redis blip is not a lost lease until the TTL since the last renewal runs out.
        Gitlab::ErrorTracking.track_exception(e)
        monotonic_time - @renewed_at < @ttl || lost!('Redis errors outlasted the lease TTL')
      end

      def lost!(reason)
        @lost_reason = reason
        Gitlab::AppLogger.warn(build_structured_payload(message: 'ClickHouse migration lock lost', reason: reason))
        false
      end

      def monotonic_time
        ::Gitlab::Metrics::System.monotonic_time
      end
    end
  end
end
