# frozen_string_literal: true

module Ai
  module ActiveContext
    module Code
      class RepositoryDeleteWorker
        include ApplicationWorker
        include Ai::ActiveContext::Concerns::Loggable
        include Gitlab::Utils::StrongMemoize
        include Gitlab::ExclusiveLeaseHelpers
        prepend ::Geo::SkipSecondary

        CONCURRENCY_LIMIT = 50

        pause_control :active_context

        feature_category :semantic_code_search
        deduplicate :until_executing
        data_consistency :sticky
        urgency :low
        idempotent!
        defer_on_database_health_signal :gitlab_main, [:p_ai_active_context_code_repositories], 10.minutes
        concurrency_limit -> { CONCURRENCY_LIMIT }

        LEASE_TRY_AFTER = 2.seconds
        LEASE_RETRIES = 2
        RETRY_IN_IF_LOCKED = 10.minutes
        LEASE_TTL = 46.minutes

        def perform(id)
          return false unless ::Ai::ActiveContext::Collections::Code.indexing?

          repository = Ai::ActiveContext::Code::Repository.find_by_id(id)

          return false unless repository&.pending_deletion?

          in_lock(lease_key(id), ttl: LEASE_TTL, sleep_sec: LEASE_TRY_AFTER, retries: LEASE_RETRIES) do
            log_deletion(repository) do
              Deleter.run!(repository)
              repository.deleted!
            end
          end
        rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
          self.class.perform_in(RETRY_IN_IF_LOCKED, id)
        end

        def lease_key(id)
          "#{self.class.name}/#{id}"
        end

        def log_deletion(repository)
          logger.info(build_structured_payload(
            message: 'Deletion started',
            ai_active_context_code_repository_id: repository.id,
            project_id: repository.project_id))

          yield

          logger.info(build_structured_payload(
            message: 'Deletion done',
            ai_active_context_code_repository_id: repository.id,
            project_id: repository.project_id))
        end
      end
    end
  end
end
