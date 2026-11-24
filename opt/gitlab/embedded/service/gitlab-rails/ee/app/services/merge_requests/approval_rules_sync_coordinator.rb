# frozen_string_literal: true

module MergeRequests
  # Coordinates approval-rule sync tracking around concurrent pushes.
  # Owns the per-(MR, sync type) Redis sets used to track in-progress
  # syncs so merge-readiness checks stay consistent while rules are
  # being rebuilt. Each tracked entry includes oldrev/newrev so
  # concurrent pushes don't clobber each other.
  #
  # Code-owner sync has two flows:
  #
  #   - Push (synchronous): callers invoke #sync_code_owners!, which
  #     wraps start -> execute -> finish in one call.
  #   - Create (async): CreateService calls #start_code_owner_sync! to
  #     pre-mark the MR before enqueuing the worker -- this closes the
  #     window where the MR could be approved before the worker runs.
  #     The worker then runs #sync_code_owners!, whose start is a no-op
  #     (SADD of the same key) and whose finish clears the pre-mark.
  #     There's no public #finish_code_owner_sync! -- the finish always
  #     happens via #sync_code_owners!.
  #
  # Reset approvals tracking is a symmetric pair:
  # #start_reset_approvals! is called when a reset is scheduled;
  # #finish_reset_approvals! is called by the reset worker when done.
  #
  # #schedule_reset_approvals! decides *when* the reset worker runs:
  # immediately if no code-owner sync is in progress, otherwise the
  # worker's params are stored in a Redis list and drained by
  # #sync_code_owners!'s ensure block once the sync completes. This
  # prevents the reset worker from running against a half-synced
  # ruleset -- the race condition the feature flag guards against.
  #
  # To close the race where a sync finishes between our
  # code_owner_sync_in_progress? check and our store, #schedule_reset_approvals!
  # re-runs the drain after storing. To close the race where a sync
  # starts between a reset worker being enqueued and Sidekiq actually
  # picking it up, #code_owner_sync_in_progress? is exposed publicly so
  # the reset worker can re-check on entry and defer via
  # #schedule_reset_approvals! if needed.
  #
  # ApprovalState delegates merge-readiness queries through here:
  # #any_sync_in_progress? feeds ApprovalState#temporarily_unapproved?
  # and #clear_sync_state! is called from
  # ApprovalState#expire_unapproved_key!. Keeping the sync key scheme
  # in one class means ApprovalState doesn't need to know about
  # SYNC_TYPES or how the cache keys are named.
  class ApprovalRulesSyncCoordinator
    PENDING_RESET_TTL = 5.minutes.to_i
    SYNC_TYPES = %i[code_owner reset_approvals].freeze
    SYNC_TTL = 5.minutes.to_i

    def initialize(merge_request, oldrev: nil, newrev: nil)
      @merge_request = merge_request
      @oldrev = oldrev
      @newrev = newrev
    end

    def sync_code_owners!
      with_sync_tracking(:code_owner, code_owner_sync_key) do
        SyncCodeOwnerApprovalRules.new(@merge_request).execute
      end
    end

    def start_code_owner_sync!
      start_approval_rules_sync!(:code_owner, code_owner_sync_key)
    end

    def start_reset_approvals!
      start_approval_rules_sync!(:reset_approvals, reset_approvals_sync_key)
    end

    def finish_reset_approvals!
      finish_approval_rules_sync!(:reset_approvals, reset_approvals_sync_key)
    end

    def schedule_reset_approvals!(project_id:, user_id:, ref:, newrev:, oldrev:)
      if code_owner_sync_in_progress?
        store_pending_reset_params!(
          project_id: project_id,
          user_id: user_id,
          ref: ref,
          newrev: newrev,
          oldrev: oldrev
        )

        # If the sync finished between our check and our store, its
        # drain ran against an empty queue and our params would be
        # stranded. Re-drain here to catch that race.
        enqueue_pending_reset_if_ready!
      else
        MergeRequestResetApprovalsWorker.perform_async(project_id, user_id, ref, newrev, oldrev)
      end
    end

    def code_owner_sync_in_progress?
      any_approval_rules_syncing?(:code_owner)
    end

    def any_sync_in_progress?
      SYNC_TYPES.any? { |type| any_approval_rules_syncing?(type) }
    end

    def clear_sync_state!
      Gitlab::Redis::SharedState.with do |redis|
        SYNC_TYPES.each { |type| redis.del(syncing_cache_key(type)) }
      end
    end

    def start_approval_rules_sync!(sync_type, sync_key)
      key = syncing_cache_key(sync_type)

      Gitlab::Redis::SharedState.with do |redis|
        redis.multi do |transaction|
          transaction.sadd?(key, sync_key)
          transaction.expire(key, SYNC_TTL)
        end
      end
    end

    def finish_approval_rules_sync!(sync_type, sync_key)
      Gitlab::Redis::SharedState.with do |redis|
        redis.srem?(syncing_cache_key(sync_type), sync_key)
      end
    end

    def any_approval_rules_syncing?(sync_type)
      Gitlab::Redis::SharedState.with do |redis|
        redis.scard(syncing_cache_key(sync_type)) > 0
      end
    end

    private

    def enqueue_pending_reset_if_ready!
      return if code_owner_sync_in_progress?

      pending_resets = fetch_and_clear_all_pending_reset_params!
      return if pending_resets.empty?

      pending_resets.each do |params|
        MergeRequestResetApprovalsWorker.perform_async(
          params['project_id'],
          params['user_id'],
          params['ref'],
          params['newrev'],
          params['oldrev']
        )
      end
    end

    def store_pending_reset_params!(params_hash)
      Gitlab::Redis::SharedState.with do |redis|
        redis.multi do |transaction|
          transaction.rpush(pending_reset_cache_key, Gitlab::Json.dump(params_hash))
          transaction.expire(pending_reset_cache_key, PENDING_RESET_TTL)
        end
      end
    end

    def fetch_and_clear_all_pending_reset_params!
      Gitlab::Redis::SharedState.with do |redis|
        results = redis.multi do |multi|
          multi.lrange(pending_reset_cache_key, 0, -1)
          multi.del(pending_reset_cache_key)
        end

        (results.first || []).filter_map { |raw| Gitlab::Json.safe_parse(raw) }
      end
    end

    def with_sync_tracking(sync_type, sync_key)
      start_approval_rules_sync!(sync_type, sync_key)
      yield
    ensure
      finish_approval_rules_sync!(sync_type, sync_key)
      enqueue_pending_reset_if_ready!
    end

    def syncing_cache_key(sync_type)
      raise ArgumentError, "Unknown sync type: #{sync_type.inspect}" unless SYNC_TYPES.include?(sync_type)

      "mr_#{@merge_request.id}_syncing_#{sync_type}"
    end

    def code_owner_sync_key
      @oldrev && @newrev ? "#{@oldrev}:#{@newrev}" : 'create'
    end

    def reset_approvals_sync_key
      raise ArgumentError, "oldrev and newrev are required for reset_approvals sync key" unless @oldrev && @newrev

      "#{@oldrev}:#{@newrev}"
    end

    def pending_reset_cache_key
      "mr_#{@merge_request.id}_pending_reset"
    end
  end
end
