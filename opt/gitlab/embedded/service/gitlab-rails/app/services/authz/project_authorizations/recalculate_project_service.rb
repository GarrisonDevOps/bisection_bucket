# frozen_string_literal: true

module Authz
  module ProjectAuthorizations
    # Recalculates one project's project_authorizations for every user: an unlocked comparison to find the
    # users whose rows are wrong, then a WriteBatchService write for those users, one chunk at a time.
    class RecalculateProjectService
      # WriteBatchService calculates and writes this many users per transaction.
      CHUNK_SIZE = WriteBatchService::BATCH_SIZE

      # @param project_id [Integer]
      # @param runtime_limiter [Gitlab::Metrics::RuntimeLimiter, nil] stops between chunks once over its limit
      def initialize(project_id, runtime_limiter: nil)
        @project_id = project_id
        @runtime_limiter = runtime_limiter
      end

      # @return [ServiceResponse] payload has :complete, false when the limiter stopped it early, :requested, the
      #   WriteBatchService::Result the comparison found, and :written, the one this run wrote
      def execute
        written = WriteBatchService::Result.new(0, 0)
        project = find_project
        return response(true, written, written) unless project

        changed, requested = changed_users(project)
        stopped = false

        changed.each_slice(CHUNK_SIZE).with_index do |chunk, index|
          if index > 0 && runtime_limiter&.over_time?
            stopped = true
            break
          end

          written += WriteBatchService.new(project_id: project_id).execute(chunk) do |ids|
            # Load the project again: the finder reads its namespace and share lock from memory, and the
            # project may have moved since the comparison.
            fresh_project = find_project
            fresh_project ? per_user_levels(fresh_project, ids) : {}
          end
        end

        response(!stopped, requested, written)
      end

      private

      attr_reader :project_id, :runtime_limiter

      def find_project
        ::Project.find_by_id(project_id)
      end

      # Users whose rows don't match the calculation, including users who lost all access. The stored rows
      # are read again after wait_for_project_writers, so a write in progress can't make a pair look unchanged.
      # @return [Array(Array<Integer>, WriteBatchService::Result)] the users, and the rows writing them would
      #   add and delete
      def changed_users(project)
        fresh, stored = ::ApplicationRecord.uncached do
          fresh = Projects::Members::EffectiveAccessLevelFinder.new(project).execute.to_h
          # Both reads from the primary: replicas can't skip dead index entries, so a read soon after a large
          # removal can time out there, and the second must see what the writers we waited for committed.
          session = ::Gitlab::Database::LoadBalancing::SessionMap.current(::ProjectAuthorization.load_balancer)
          stored_user_ids = session.use_primary { ::ProjectAuthorization.stored_levels_for_project(project_id).keys }
          WriteBatchService.wait_for_project_writers(project_id, fresh.keys | stored_user_ids)

          [fresh, session.use_primary { ::ProjectAuthorization.stored_levels_for_project(project_id) }]
        end

        changed = (fresh.keys | stored.keys).reject do |user_id|
          WriteBatchService.unchanged?(stored.fetch(user_id, []), fresh[user_id])
        end

        # Blocked users keep their rows until they are active again.
        skipped = BlockedUserRefreshSkip.skipped_user_ids(changed, skipped_in: :project_recalculate)
        changed = changed.reject { |user_id| skipped.include?(user_id) }

        requested = WriteBatchService::Result.new(
          changed.count { |user_id| fresh[user_id] },
          changed.sum { |user_id| stored.fetch(user_id, []).size }
        )

        [changed, requested]
      end

      def per_user_levels(project, user_ids)
        Projects::Members::EffectiveAccessLevelPerUserFinder.new(project, user_ids).execute.to_h
      end

      def response(complete, requested, written)
        ServiceResponse.success(payload: { complete: complete, requested: requested, written: written })
      end
    end
  end
end
