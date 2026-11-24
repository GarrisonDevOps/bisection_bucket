# frozen_string_literal: true

module Mcp
  module Audit
    # Closes inferred MCP sessions whose sliding window has lapsed. MCP clients
    # never signal disconnection, so a session only ends by timing out.
    class CloseIdleSessionsService
      BATCH_SIZE = 1_000
      STALE_AFTER = 1.hour
      # Both passes read the oldest sessions first, so a run that stops here
      # resumes where it left off on the next cron tick.
      MAX_RUNTIME = 3.minutes

      def execute
        @runtime_limiter = ::Gitlab::Metrics::RuntimeLimiter.new(MAX_RUNTIME)

        close_lapsed_sessions
        close_stale_sessions
      end

      private

      attr_reader :runtime_limiter

      # Driven by a sorted set rather than a scan over the Redis keyspace.
      # A batch that resolved nothing is only left with entries this run must
      # not touch, so looping again would re-read the same front of the set.
      def close_lapsed_sessions
        cutoff = Time.current.to_i

        loop do
          tracked_ids = lapsed_session_ids(cutoff)
          break if tracked_ids.empty?

          resolved = close_lapsed_batch(tracked_ids, cutoff)

          break if resolved == 0 || tracked_ids.size < BATCH_SIZE || runtime_limiter.over_time?
        end
      end

      # Returns how many ids the batch took out of the set, which is what tells
      # the caller whether another read can make progress.
      def close_lapsed_batch(tracked_ids, cutoff)
        open_sessions = mcp_sessions.id_in(tracked_ids).with_user.to_a
        scores = scores_for(open_sessions)

        # The scores are re-read because a tool call can extend a window between
        # the range read and here. Finishing a session that is live again would
        # send the next tool call's events to a finished session, since that call
        # still resumes it from its own Redis key.
        lapsed = open_sessions.reject { |session| extended_since?(scores[session.id], cutoff) }

        # The score is the instant the window lapsed. The sweep can run minutes
        # later, so recording its own clock would overstate every session.
        close(lapsed.index_with { |session| Time.zone.at(scores[session.id] || cutoff) })

        # An id with no running row left was destroyed or is already finished.
        # Nothing can re-add it, so the entry is dead weight and the set would
        # otherwise grow without bound.
        dead_ids = tracked_ids - open_sessions.map { |session| session.id.to_s }
        untrack_ids(dead_ids)

        lapsed.size + dead_ids.size
      end

      # Redis holds the window, so losing it would otherwise leave sessions
      # running for ever.
      def close_stale_sessions
        loop do
          sessions = mcp_sessions.stale_since(STALE_AFTER.ago).oldest_first.limit(BATCH_SIZE).with_user.to_a

          close(sessions.index_with { |session| stale_finished_at(session) })

          break if sessions.size < BATCH_SIZE || runtime_limiter.over_time?
        end
      end

      # No window outlives MAX_DURATION, so that is when the session ended, however
      # long ago Redis lost the entry. Capped at now for a row young enough that the
      # cap is still ahead of it, which a clock skew or a short STALE_AFTER allows.
      def stale_finished_at(session)
        [session.session_started_at + ResolveSessionService::MAX_DURATION, Time.current].min
      end

      # Rows are finished before the events are enqueued, because a re-emitted
      # session_ended carries a fresh cloud_event_id that no destination can dedupe.
      # One statement, so a failure leaves no half-finished batch behind: the next
      # run retries the batch whole rather than inheriting rows it cannot find.
      def close(finished_at_by_session)
        return [] if finished_at_by_session.empty?

        finished = bulk_finish(finished_at_by_session)

        # Enqueued before the untrack, because a lost ZREM is repaired by the
        # dead-id prune on the next run and a lost enqueue is repaired by nothing.
        emit_session_ended(finished)
        untrack_ids(finished_at_by_session.keys.map(&:id))

        finished
      end

      def lapsed_session_ids(cutoff)
        with_redis do |redis|
          redis.zrangebyscore(
            ResolveSessionService::OPEN_SESSIONS_KEY, 0, cutoff, limit: [0, BATCH_SIZE]
          )
        end
      end

      # One ZMSCORE for the batch, rather than a ZSCORE per session.
      def scores_for(sessions)
        return {} if sessions.empty?

        ids = sessions.map(&:id)
        scores = with_redis { |redis| redis.zmscore(ResolveSessionService::OPEN_SESSIONS_KEY, *ids) }

        ids.zip(scores).to_h
      end

      def extended_since?(score, cutoff)
        score.present? && score > cutoff
      end

      # One ZREM for the batch, rather than one per session.
      def untrack_ids(ids)
        return if ids.empty?

        with_redis { |redis| redis.zrem(ResolveSessionService::OPEN_SESSIONS_KEY, ids) }
      end

      def mcp_sessions
        ::Ai::Governance::Session.mcp.running
      end

      # Returns only the sessions the statement finished, so a run that overlaps another,
      # as a deferred run can, does not send session_ended for rows the other closed.
      def bulk_finish(finished_at_by_session)
        updated_at = Time.current
        finished_ids = ::Ai::Governance::Session.finish_running!(
          finished_at_by_session.transform_keys(&:id), updated_at: updated_at
        ).to_set

        finished_at_by_session.filter_map do |session, finished_at|
          next unless finished_ids.include?(session.id)

          sync_finished_attributes(session, finished_at, updated_at)
          session
        end
      end

      # The statement writes past the model, so the loaded rows still carry their
      # old values. Matching them to the database keeps that an implementation
      # detail rather than a trap for whoever reads them next.
      def sync_finished_attributes(session, finished_at, updated_at)
        session.assign_attributes(status: :finished, session_finished_at: finished_at, updated_at: updated_at)
        session.changes_applied
      end

      # One job for the batch rather than one per session. The batch spans every
      # namespace the sweep touched, so there is no single scope to put in the
      # application context, for the same reason the worker disables
      # Scalability/CronWorkerContext.
      def emit_session_ended(sessions)
        # `user` is optional on the model, so a deleted account leaves the session
        # closable with nobody to attribute the event to.
        payloads = sessions.filter_map do |session|
          next unless session.user

          ::Mcp::Audit::CaptureEventService.new(
            current_user: session.user,
            session: session,
            kind: :session_ended
          ).job_attributes
        end

        return if payloads.empty?

        ::Ai::DuoWorkflows::ProcessAuditEventsWorker.perform_async(payloads)
      end

      def with_redis(&block)
        # rubocop:disable CodeReuse/ActiveRecord -- Redis connection pool, not ActiveRecord
        ::Gitlab::Redis::SharedState.with(&block)
        # rubocop:enable CodeReuse/ActiveRecord
      end
    end
  end
end
