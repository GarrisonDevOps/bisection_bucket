# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module SessionCredits
      # Per root namespace sync freshness in three sorted sets: last complete sync, last tick seen in
      # scope, and stay start, so a group back after days of inactivity is not reported stale.
      # Redis errors are swallowed: this is observability and must never fail a sync.
      module SyncFreshness
        # Hash-tagged so the keys share a slot on Redis Cluster.
        KEY_PREFIX = 'duo_workflow_session_credits_v2:{freshness}'
        COMPLETED_KEY = "#{KEY_PREFIX}:completed".freeze
        SEEN_KEY = "#{KEY_PREFIX}:seen".freeze
        ENTERED_KEY = "#{KEY_PREFIX}:entered".freeze
        OBSERVED_KEY = "#{KEY_PREFIX}:observed_at".freeze
        # Self-managed syncs once for the whole instance, with no root namespace.
        INSTANCE_MEMBER = 'instance'
        # Measured against the previous observed tick, not the clock, so a cron outage does
        # not end every stay. Missing from one 6-hour tick keeps the stay; from two ends it.
        SCOPE_GAP = 7.hours
        # Namespaces out of scope this long, and completions this old, are dropped. Every
        # write also refreshes the keys' TTL, so the sets go away once the sync stops for good.
        RETENTION = 90.days
        BATCH_SIZE = 1_000
        # An edge at every threshold the alert may use.
        AGE_BUCKETS = [6, 12, 16, 18, 24, 48, 168].map { |hours| hours * 3600 }.freeze

        # Records a complete sync for a root namespace, or for the instance when it is nil.
        #
        # @param root_namespace_id [Integer, nil]
        # @return [void]
        def self.record_completion(root_namespace_id)
          with_redis do |redis|
            redis.pipelined do |pipeline|
              pipeline.zadd(COMPLETED_KEY, Time.current.to_i, member_for(root_namespace_id), gt: true)
              pipeline.expire(COMPLETED_KEY, RETENTION.to_i)
            end
          end

          nil
        end

        # The oldest last complete sync across the given root namespaces, so a scope is only
        # as fresh as its least recently synced namespace. A nil ID reads the instance.
        #
        # @param root_namespace_ids [Array<Integer, nil>]
        # @return [ActiveSupport::TimeWithZone, nil] nil when any of them never completed a
        #   sync, or on a Redis error
        def self.oldest_completed_at(root_namespace_ids)
          members = root_namespace_ids.map { |id| member_for(id) }.uniq
          return if members.empty?

          scores = with_redis { |redis| redis.zmscore(COMPLETED_KEY, *members) }
          return if scores.nil? || scores.any?(&:nil?)

          to_time(scores.min)
        end

        # For support questions about one namespace.
        def self.status(root_namespace_id)
          member = member_for(root_namespace_id)
          completed, seen, entered = with_redis do |redis|
            redis.pipelined do |pipeline|
              [COMPLETED_KEY, SEEN_KEY, ENTERED_KEY].each { |key| pipeline.zscore(key, member) }
            end
          end

          {
            last_completed_at: to_time(completed),
            last_seen_in_scope_at: to_time(seen),
            in_scope_since: to_time(entered)
          }
        end

        # Records this tick's in-scope namespaces and observes each one's age: since its last
        # complete sync, or, while it awaits its first complete sync of this stay, since the
        # stay began. Returns the figures for the cron's done line, or nil on a Redis error.
        def self.observe(root_namespace_ids)
          now = Time.current.to_i
          stats = { oldest_sync_age_s: 0, oldest_awaiting_sync_s: 0, namespaces_awaiting_sync: 0 }
          synced = sync_age_histogram
          awaiting = awaiting_sync_histogram
          observed_at = previous_observation(now)
          return unless observed_at

          # Every batch is read before any histogram is observed, so a Redis error mid-way
          # reports nothing rather than part of the scope.
          batches = Array(root_namespace_ids).each_slice(BATCH_SIZE).map do |ids|
            ages_for(ids.map(&:to_s), now, observed_at)
          end
          return if batches.any?(&:nil?)

          batches.flatten(1).each do |age, awaiting_sync|
            if awaiting_sync
              awaiting.observe({}, age)
              stats[:namespaces_awaiting_sync] += 1
              stats[:oldest_awaiting_sync_s] = [stats[:oldest_awaiting_sync_s], age].max
            else
              synced.observe({}, age)
              stats[:oldest_sync_age_s] = [stats[:oldest_sync_age_s], age].max
            end
          end

          with_redis { |redis| redis.set(OBSERVED_KEY, now, ex: RETENTION.to_i) }
          prune(now)
          stats
        end

        # Built inside a method: a class-body metric is evaluated at constantize time and
        # breaks server_metrics_spec. Public so Sidekiq can create the zero series at boot.
        def self.sync_age_histogram
          ::Gitlab::Metrics.histogram(
            :duo_workflow_session_credits_v2_sync_age_seconds,
            'Seconds since the last complete v2 session credits sync, per in-scope root namespace and tick',
            {},
            AGE_BUCKETS
          )
        end

        def self.awaiting_sync_histogram
          ::Gitlab::Metrics.histogram(
            :duo_workflow_session_credits_v2_awaiting_sync_seconds,
            'Seconds in scope without a complete v2 session credits sync, per root namespace and tick',
            {},
            AGE_BUCKETS
          )
        end

        # The previous observed tick, or now on the first one ever; nil on a Redis error.
        def self.previous_observation(now)
          stored = with_redis { |redis| [redis.get(OBSERVED_KEY)] }
          return unless stored

          stored.first&.to_i || now
        end
        private_class_method :previous_observation

        # Returns [age, awaiting_sync] per member, after recording this tick's sighting.
        def self.ages_for(members, now, observed_at)
          completed, seen, entered = with_redis do |redis|
            redis.pipelined do |pipeline|
              [COMPLETED_KEY, SEEN_KEY, ENTERED_KEY].each { |key| pipeline.zmscore(key, *members) }
            end
          end
          return unless completed

          starts = stay_starts(seen, entered, now, observed_at)

          stored = with_redis do |redis|
            redis.pipelined do |pipeline|
              pipeline.zadd(SEEN_KEY, members.map { |member| [now, member] })
              pipeline.zadd(ENTERED_KEY, members.zip(starts).map(&:reverse))
              [SEEN_KEY, ENTERED_KEY].each { |key| pipeline.expire(key, RETENTION.to_i) }
            end
          end
          return unless stored

          members.each_index.map do |index|
            synced_at = completed[index]&.to_i

            synced_at && synced_at >= starts[index] ? [now - synced_at, false] : [now - starts[index], true]
          end
        end
        private_class_method :ages_for

        # A namespace last seen more than the scope gap before the previous observed tick
        # starts a new stay now.
        def self.stay_starts(seen, entered, now, observed_at)
          seen.zip(entered).map do |seen_at, entered_at|
            new_stay = seen_at.nil? || entered_at.nil? || seen_at < observed_at - SCOPE_GAP.to_i
            new_stay ? now : entered_at.to_i
          end
        end
        private_class_method :stay_starts

        # Stays are pruned by their last sighting, not their start, which can be older than
        # the retention for a namespace active all along.
        def self.prune(now)
          cutoff = now - RETENTION.to_i

          with_redis do |redis|
            gone = redis.zrangebyscore(SEEN_KEY, '-inf', cutoff)

            gone.each_slice(BATCH_SIZE) do |members|
              [COMPLETED_KEY, SEEN_KEY, ENTERED_KEY].each { |key| redis.zrem(key, members) }
            end

            # Catches completions recorded for a namespace no tick has seen.
            redis.zremrangebyscore(COMPLETED_KEY, '-inf', cutoff)
          end
        end
        private_class_method :prune

        def self.to_time(score)
          Time.zone.at(score.to_i) if score
        end
        private_class_method :to_time

        def self.member_for(root_namespace_id)
          root_namespace_id.nil? ? INSTANCE_MEMBER : root_namespace_id.to_s
        end
        private_class_method :member_for

        def self.with_redis(&block)
          ::Gitlab::Redis::SharedState.with(&block) # rubocop:disable CodeReuse/ActiveRecord -- redis pool, not active record
        rescue ::Redis::BaseError, ::RedisClient::Error => e
          ::Gitlab::ErrorTracking.track_exception(e)
          nil
        end
        private_class_method :with_redis
      end
    end
  end
end
