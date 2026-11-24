# frozen_string_literal: true

module BatchedGitRefUpdates
  class ProjectCleanupService
    include ::Gitlab::ExclusiveLeaseHelpers

    LOCK_TIMEOUT = 10.minutes
    GITALY_BATCH_SIZE = 100
    QUERY_BATCH_SIZE = 1000
    MAX_DELETES = 10_000

    BACKOFF_BASE = 1.minute
    BACKOFF_MAX = 1.day
    BACKOFF_KEY_PREFIX = 'batched_git_ref_updates:project_cleanup:backoff'

    REPAIR_SOURCE = 'batched_git_ref_updates_repair'

    def initialize(project_id)
      @project_id = project_id
    end

    def execute
      retry_after = backoff_retry_after
      return { total_deletes: 0, skipped_until: retry_after } if retry_after&.future?

      total_deletes = 0

      in_lock("#{self.class}/#{@project_id}", retries: 0, ttl: LOCK_TIMEOUT) do
        # use primary so we don't incorrectly drop Deletion records due to replication delay
        project = ::Gitlab::Database::LoadBalancing::SessionMap.with_sessions.use_primary do
          Project.find_by_id(@project_id)
        end

        Deletion
          .status_pending
          .for_project(@project_id)
          .select_ref_and_identity
          .each_batch(of: QUERY_BATCH_SIZE) do |batch|
          refs = batch.map(&:ref)

          if project
            begin
              refs.each_slice(GITALY_BATCH_SIZE) do |refs_to_delete|
                delete_refs_with_repair(project, refs_to_delete.uniq)
              end
            rescue Gitlab::Git::Repository::NoRepository
              # Repository is gone, refs are effectively deleted
            end
          end

          total_deletes += refs.count
          Deletion.mark_records_processed(batch)

          break if total_deletes >= MAX_DELETES
        end
      end

      clear_backoff

      { total_deletes: total_deletes }
    rescue Gitlab::Git::BaseError => e
      # a run that deleted something before failing is not a stuck project
      clear_backoff if total_deletes.to_i > 0
      record_failure(e)
      raise
    end

    private

    def delete_refs_with_repair(project, refs)
      project.repository.delete_refs(*refs)
    rescue Gitlab::Git::ReferenceConflictError => e
      raise unless Feature.enabled?(:batched_git_ref_updates_repair_stray_parent, project, type: :gitlab_com_derisk)

      repair_stray_parent(project, e)

      project.repository.delete_refs(*refs)
    end

    def repair_stray_parent(project, error)
      parent = error.existing_reference_name

      unless error.conflicting_reference_name.start_with?("#{parent}/")
        repair_failed!(project, error, 'existing reference is not a parent of the reference being deleted')
      end

      commit = project.repository.commit(parent)
      repair_failed!(project, error, 'parent commit could not be resolved') unless commit

      failed = project.repository.keep_around(commit.sha, source: REPAIR_SOURCE)
      repair_failed!(project, error, 'keep-around reference could not be written') if failed.present?

      # KeepAround also writes nothing, without reporting it, when keep-around
      # references are disabled. The commit must stay reachable before the
      # parent goes, so check the reference rather than trust the return value.
      keep_around_ref = "refs/#{::Repository::REF_KEEP_AROUND}/#{commit.sha}"
      unless project.repository.ref_exists?(keep_around_ref)
        repair_failed!(project, error, 'keep-around reference was not written')
      end

      project.repository.delete_refs(parent)

      Gitlab::AppLogger.info(
        message: 'Repaired stray parent reference blocking batched ref deletion',
        gl_project_id: project.id,
        ref: parent,
        conflicting_ref: error.conflicting_reference_name,
        kept_around: commit.sha
      )
    end

    def repair_failed!(project, error, reason)
      Gitlab::AppLogger.warn(
        message: 'Could not repair stray parent reference blocking batched ref deletion',
        gl_project_id: project.id,
        ref: error.existing_reference_name,
        conflicting_ref: error.conflicting_reference_name,
        repair_failure: reason
      )

      raise Gitlab::Git::ReferenceConflictError.new(
        existing_reference_name: error.existing_reference_name,
        conflicting_reference_name: error.conflicting_reference_name,
        reason: reason
      )
    end

    def backoff_key
      "#{BACKOFF_KEY_PREFIX}:#{@project_id}"
    end

    def backoff_retry_after
      value = Gitlab::Redis::SharedState.with { |redis| redis.hget(backoff_key, 'retry_after') }

      Time.zone.at(value.to_i) if value
    end

    def record_failure(error)
      Gitlab::Redis::SharedState.with do |redis|
        failures = redis.hincrby(backoff_key, 'failures', 1)
        delay = [BACKOFF_BASE * (2**(failures - 1)), BACKOFF_MAX].min
        retry_after = delay.from_now

        redis.hset(backoff_key, 'retry_after', retry_after.to_i)
        redis.expire(backoff_key, (delay + BACKOFF_MAX).to_i)

        Gitlab::AppLogger.warn(
          message: 'Batched ref deletion failed; backing off',
          gl_project_id: @project_id,
          consecutive_failures: failures,
          retry_after: retry_after.iso8601,
          error_class: error.class.name
        )
      end
    end

    def clear_backoff
      Gitlab::Redis::SharedState.with { |redis| redis.del(backoff_key) }
    end
  end
end
