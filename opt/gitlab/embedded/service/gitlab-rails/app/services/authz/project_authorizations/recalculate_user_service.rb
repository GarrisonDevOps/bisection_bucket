# frozen_string_literal: true

module Authz
  module ProjectAuthorizations
    # Recalculates one user's project_authorizations on the projects a change can affect.
    #
    # With groups, those are the projects the user's memberships in them can reach, so a change costs the size
    # of those reaches, not the user's whole access. With project IDs, just those. With neither, every project
    # the user can have access to, for repairs.
    #
    # The projects are taken in sorted slices. Each slice is compared without the lock, and only its changed
    # projects are recalculated and written under it, so the unchanged majority never takes the lock. A run
    # stopped by the runtime limiter returns a cursor, and the next run resumes after it.
    class RecalculateUserService
      # Matches WriteBatchService's chunks, so each slice's changes are written in one transaction.
      SLICE_SIZE = WriteBatchService::BATCH_SIZE

      # @param user_id [Integer]
      # @param group_ids [Array<Integer>, nil]
      # @param project_ids [Array<Integer>, nil]
      # @param cursor [Integer, nil] the last project ID an earlier run finished; only later ones are done
      # @param runtime_limiter [Gitlab::Metrics::RuntimeLimiter, nil] stops between slices once over its limit
      def initialize(user_id, group_ids: nil, project_ids: nil, cursor: nil, runtime_limiter: nil)
        @user_id = user_id
        @group_ids = group_ids
        @project_ids = project_ids
        @cursor = cursor
        @runtime_limiter = runtime_limiter
      end

      # Must be called outside any transaction, like WriteBatchService.
      #
      # @return [ServiceResponse] payload has :complete, the :cursor to resume from when it stopped early, and
      #   :written, the WriteBatchService::Result of the rows this run wrote
      def execute
        written = WriteBatchService::Result.new(0, 0)
        user = ::User.find_by_id(user_id)
        return response(nil, written) unless user
        return response(nil, written) if BlockedUserRefreshSkip.skip_and_log?(user, skipped_in: :user_refresh)

        # Before reading any stored rows: a writer still holding the lock may commit a result calculated before
        # this change, after we've compared against its old rows. Writers that start later see the change.
        WriteBatchService.wait_for_user_writers(user_id)

        finished = nil
        stopped = false
        candidate_project_ids.each_slice(SLICE_SIZE) do |slice|
          # The first slice always runs, so every run makes progress.
          if finished && runtime_limiter&.over_time?
            stopped = true
            break
          end

          changed = changed_project_ids(slice)
          written += WriteBatchService.new(user_id: user_id).execute(changed) { |ids| calculate(ids) } if changed.any?
          finished = slice.last
        end

        response(stopped ? finished : nil, written)
      end

      private

      attr_reader :user_id, :group_ids, :project_ids, :cursor, :runtime_limiter

      # Without the lock. WriteBatchService recalculates the changed projects under it, so an answer that is
      # stale by then only costs work.
      def changed_project_ids(slice)
        fresh = calculate(slice)
        stored = ::ProjectAuthorization.stored_levels_for_user(user_id, slice)

        slice.reject { |id| WriteBatchService.unchanged?(stored.fetch(id, []), fresh[id]) }
      end

      # A new instance each time, so nothing read before the lock is reused under it.
      def calculate(ids)
        ::ApplicationRecord.uncached do
          UserProjectGrants.new(user_id, cached: false).max_access_levels(ids)
        end
      end

      # Sorted, so a cursor means the same thing in every run.
      def candidate_project_ids
        ids = ::ApplicationRecord.uncached do
          if project_ids
            project_ids
          elsif group_ids
            Reach.new(group_ids).project_ids
          else
            Reach.for_user(user_id)
          end
        end

        ids = ids.uniq.sort
        cursor ? ids.select { |id| id > cursor } : ids
      end

      def response(cursor, written)
        ServiceResponse.success(payload: { complete: cursor.nil?, cursor: cursor, written: written })
      end
    end
  end
end
