# frozen_string_literal: true

module Ci
  class ArchiveTraceService
    include ::Gitlab::ExclusiveLeaseHelpers

    EXCLUSIVE_LOCK_KEY = 'archive_trace_service:batch_execute:lock'
    LOCK_TIMEOUT = 56.minutes
    LOOP_TIMEOUT = 55.minutes
    LOOP_LIMIT = 2000
    BATCH_SIZE = 100
    CURSOR_KEY = 'ci:archive_trace_service:batch_execute:cursor'
    # Past the trace chunks' Redis TTL, builds the cursor skipped have lost their logs anyway.
    CURSOR_TTL = Ci::BuildTraceChunks::RedisBase::CHUNK_REDIS_TTL

    def batch_execute(worker_name:)
      unless Feature.enabled?(:ci_archive_traces_cron_cursor, :instance)
        return legacy_batch_execute(worker_name: worker_name)
      end

      start_time = Time.current
      stats = { processed: 0, skipped_archived_pipeline: 0, limit_reached: false, over_time: false }

      in_lock(EXCLUSIVE_LOCK_KEY, ttl: LOCK_TIMEOUT, retries: 1) do
        cursor, pass_end = read_cursor
        # Builds could keep getting chunks faster than a window is read, so a pass stops at the newest
        # build when it started. Without the bound it would chase new builds and never finish.
        pass_end ||= Ci::BuildTraceChunk.last_build_id || 0
        stats[:cursor_start] = cursor
        stats[:pass_end] = pass_end

        loop do
          break stats[:over_time] = true if over_time?(start_time)

          build_keys = Ci::BuildTraceChunk.build_keys_after(cursor, up_to: pass_end, limit: BATCH_SIZE)
          break cursor = nil if build_keys.empty?

          Ci::Build.stale_with_keys(build_keys).eager_load_for_archiving_trace.each do |build|
            # Skipped here so they don't use up the loop limit.
            if archived_pipeline?(build)
              cursor = build.id
              stats[:skipped_archived_pipeline] += 1
              next
            end

            if stats[:processed] >= LOOP_LIMIT
              Sidekiq.logger.warn(class: worker_name, message: 'Loop limit reached.', job_id: build.id)
              break stats[:limit_reached] = true
            end

            break stats[:over_time] = true if over_time?(start_time)

            cursor = build.id
            stats[:processed] += 1
            archive_stale_build(build, worker_name)
          end

          stopped = stats[:limit_reached] || stats[:over_time]
          # Jump past builds that aren't stale yet, or the same window is read again.
          # The next pass picks them up if Ci::ArchiveTraceWorker hasn't archived them.
          cursor = build_keys.last.first unless stopped
          # Saved per window, so an interrupted or failing run keeps its progress.
          write_cursor(cursor, pass_end)
          break if stopped
        end

        stats[:completed_cycle] = cursor.nil?
        stats[:cursor_end] = cursor
        write_cursor(cursor, pass_end)
      end

      stats
    end

    def execute(job, worker_name:)
      return if job.pipeline.archived?

      unless job.trace.archival_attempts_available?
        Sidekiq.logger.warn(class: worker_name, message: 'The job is out of archival attempts.', job_id: job.id)

        job.trace.attempt_archive_cleanup!
        return
      end

      unless job.trace.can_attempt_archival_now?
        Sidekiq.logger.warn(class: worker_name, message: 'The job can not be archived right now.', job_id: job.id)
        return
      end

      # Archival updates and then deletes the build's trace metadata row, so the
      # isolation check triggered by that update is a guaranteed no-op.
      # See https://gitlab.com/gitlab-org/gitlab/-/issues/606395
      Organizations::Sharding.skip_isolation_check { job.trace.archive! }
      job.remove_pending_state!

      if job.job_artifacts_trace.present?
        job.project.execute_integrations(Gitlab::DataBuilder::ArchiveTrace.build(job), :archive_trace_hooks)
      end
    rescue ::Gitlab::Ci::Trace::AlreadyArchivedError
      # It's already archived, thus we can safely ignore this exception.
    rescue StandardError => e
      job.trace.increment_archival_attempts!

      # Tracks this error with application logs, Sentry, and Prometheus.
      # If `archive!` keeps failing for over a week, that could incur data loss.
      # (See more https://docs.gitlab.com/administration/cicd/job_logs/#incremental-logging)
      # In order to avoid interrupting the system, we do not raise an exception here.
      archive_error(e, job, worker_name)
    end

    private

    # rubocop: disable CodeReuse/ActiveRecord -- existing query, removed with the ci_archive_traces_cron_cursor flag
    def legacy_batch_execute(worker_name:)
      start_time = Time.current
      in_lock(EXCLUSIVE_LOCK_KEY, ttl: LOCK_TIMEOUT, retries: 1) do
        Ci::Build.with_stale_live_trace.eager_load_for_archiving_trace
          .find_each(batch_size: BATCH_SIZE).with_index do |build, index|
          break if Time.current - start_time > LOOP_TIMEOUT

          if index > LOOP_LIMIT
            Sidekiq.logger.warn(class: worker_name, message: 'Loop limit reached.', job_id: build.id)
            break
          end

          begin
            execute(build, worker_name: worker_name)
          rescue StandardError
            next
          end
        end
      end
    end
    # rubocop: enable CodeReuse/ActiveRecord

    # One failing build mustn't stop the run; execute already reports archival errors.
    def archive_stale_build(build, worker_name)
      execute(build, worker_name: worker_name)
    rescue StandardError
      nil
    end

    # Their trace metadata partitions may be detached, so they can't be archived.
    # A build without a pipeline goes to execute instead, which records the failure.
    def archived_pipeline?(build)
      build.pipeline&.archived?
    end

    def over_time?(start_time)
      Time.current - start_time > LOOP_TIMEOUT
    end

    # Returns [cursor, pass_end]. A missing cursor starts a new pass from 0 with no pass end yet.
    def read_cursor
      cursor, pass_end = Gitlab::Redis::SharedState.with { |redis| redis.hmget(CURSOR_KEY, 'cursor', 'pass_end') }

      # An unreadable value starts a new pass instead of failing every run until the key expires.
      [Integer(cursor, exception: false) || 0, Integer(pass_end, exception: false)]
    end

    # Both values live in one hash so they expire together, and a nil cursor ends the pass.
    def write_cursor(cursor, pass_end)
      Gitlab::Redis::SharedState.with do |redis|
        next redis.del(CURSOR_KEY) if cursor.nil?

        redis.pipelined do |pipeline|
          pipeline.hset(CURSOR_KEY, 'cursor', cursor, 'pass_end', pass_end)
          pipeline.expire(CURSOR_KEY, CURSOR_TTL)
        end
      end
    end

    def failed_archive_counter
      @failed_archive_counter ||=
        Gitlab::Metrics.counter(:job_trace_archive_failed_total, "Counter of failed attempts of trace archiving")
    end

    def archive_error(error, job, worker_name)
      failed_archive_counter.increment

      Sidekiq.logger.warn(
        class: worker_name,
        message: "Failed to archive trace. message: #{error.message}.",
        job_id: job.id
      )

      Gitlab::ErrorTracking.track_and_raise_for_dev_exception(
        error,
        issue_url: 'https://gitlab.com/gitlab-org/gitlab-foss/issues/51502',
        job_id: job.id
      )
    end
  end
end
