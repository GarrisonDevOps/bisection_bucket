# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    # Cooldown between re-resolutions of an open remediation merge request, so an open MR
    # picks up a newer patched version without running an update workload on every pipeline.
    #
    # Owns the window for both sides: it starts whenever an MR is brought up to date or gets a
    # conflict refresh, and SchedulerService consumes it when deciding to refresh. A second key,
    # per branch head, limits a conflicted MR to one refresh per head per period. Losing either
    # key costs at most one extra refresh, so plain expiring keys are enough.
    module RefreshCooldown
      PERIOD = 8.hours
      KEY_PREFIX = 'dependency_management:remediation_refresh'
      CONFLICT_KEY_PREFIX = 'dependency_management:remediation_conflict_refresh'

      # Starts the window, so the merge request is left alone until it elapses. Called when the
      # merge request is created or updated, as it then reflects the latest resolution, and by a
      # conflict refresh, which counts as the window's refresh.
      def self.start(merge_request)
        ::Gitlab::Redis::SharedState.with do |redis|
          redis.set(key_for(merge_request), 1, ex: PERIOD.to_i)
        end
      rescue ::Redis::BaseError, ::RedisClient::Error => e
        ::Gitlab::ErrorTracking.track_exception(e, merge_request_id: merge_request.id)

        nil
      end

      # @return [Boolean] true once the window has elapsed and the merge request may be
      # re-resolved. Consumes the window, so a refresh is attempted at most once per window
      # even when it never reaches the merge request - e.g. its workload fails. The set and
      # the read are one operation, so concurrent schedulers cannot both claim it.
      #
      # Reports false when Redis is unreachable: the cooldown cannot be established, so the
      # safe answer is to leave the merge request alone rather than refresh every open
      # remediation on every pipeline.
      def self.elapsed?(merge_request)
        ::Gitlab::Redis::SharedState.with do |redis|
          redis.set(key_for(merge_request), 1, ex: PERIOD.to_i, nx: true)
        end
      rescue ::Redis::BaseError, ::RedisClient::Error => e
        ::Gitlab::ErrorTracking.track_exception(e, merge_request_id: merge_request.id)

        false
      end

      # Holds this branch head for the period, so no conflict refresh starts on it. Called on a
      # cooldown refresh, whose workload leaves the head as it was unless it commits.
      def self.hold_head(merge_request)
        key = conflict_key_for(merge_request)
        return unless key

        ::Gitlab::Redis::SharedState.with { |redis| redis.set(key, 1, ex: PERIOD.to_i) }
      rescue ::Redis::BaseError, ::RedisClient::Error => e
        ::Gitlab::ErrorTracking.track_exception(e, merge_request_id: merge_request.id)

        nil
      end

      # Frees this branch head for a conflict refresh. Called when a refresh skips its commit,
      # which happens only while the merge request is not known to be conflicted.
      def self.release_head(merge_request)
        key = conflict_key_for(merge_request)
        return unless key

        ::Gitlab::Redis::SharedState.with { |redis| redis.del(key) }
      rescue ::Redis::BaseError, ::RedisClient::Error => e
        ::Gitlab::ErrorTracking.track_exception(e, merge_request_id: merge_request.id)

        nil
      end

      # @return [Boolean] true, claiming it, when no refresh holds this branch head. A refresh that
      # doesn't commit keeps the head, so the next one waits for the period; a commit moves the
      # head. False when Redis is unreachable, as for elapsed?.
      def self.conflict_refresh_due?(merge_request)
        key = conflict_key_for(merge_request)
        return false unless key

        ::Gitlab::Redis::SharedState.with { |redis| redis.set(key, 1, ex: PERIOD.to_i, nx: true) }
      rescue ::Redis::BaseError, ::RedisClient::Error => e
        ::Gitlab::ErrorTracking.track_exception(e, merge_request_id: merge_request.id)

        false
      end

      def self.key_for(merge_request)
        "#{KEY_PREFIX}:#{merge_request.id}"
      end
      private_class_method :key_for

      def self.conflict_key_for(merge_request)
        sha = merge_request.source_branch_sha
        "#{CONFLICT_KEY_PREFIX}:#{merge_request.id}:#{sha}" if sha
      end
      private_class_method :conflict_key_for
    end
  end
end
