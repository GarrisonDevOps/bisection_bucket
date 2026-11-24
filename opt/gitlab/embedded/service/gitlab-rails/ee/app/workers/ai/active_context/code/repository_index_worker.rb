# frozen_string_literal: true

module Ai
  module ActiveContext
    module Code
      class RepositoryIndexWorker
        include ApplicationWorker
        include Ai::ActiveContext::Concerns::Loggable
        include Gitlab::Utils::StrongMemoize
        include Gitlab::ExclusiveLeaseHelpers
        prepend ::Geo::SkipSecondary

        CONCURRENCY_LIMIT = 50

        pause_control :active_context

        feature_category :semantic_code_search
        deduplicate :until_executing, including_scheduled: true
        data_consistency :sticky
        urgency :low
        idempotent!
        defer_on_database_health_signal :gitlab_main, [:p_ai_active_context_code_repositories], 10.minutes
        concurrency_limit -> { CONCURRENCY_LIMIT }

        LEASE_TRY_AFTER = 2.seconds
        LEASE_RETRIES = 2
        RETRY_IN_IF_LOCKED = 10.minutes
        PUSH_INDEXING_DELAY = 2.minutes
        SHORT_PUSH_INDEXING_DELAY = 1.minute
        LEASE_TTL = 46.minutes

        def self.perform_with_push_delay(repository)
          project_actor = Project.actor_from_id(repository.project_id)

          if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) &&
              Feature.enabled?(:active_context_code_push_indexing_delay, project_actor, type: :gitlab_com_derisk)
            delay =
              if Feature.enabled?(:active_context_code_push_indexing_delay_1m, project_actor, type: :gitlab_com_derisk)
                SHORT_PUSH_INDEXING_DELAY
              else
                PUSH_INDEXING_DELAY
              end

            perform_in(delay, repository.id)
          else
            perform_async(repository.id)
          end
        end

        def perform(id)
          return false unless ::Ai::ActiveContext::Collections::Code.indexing?

          repository = Ai::ActiveContext::Code::Repository.find_by_id(id)

          return false unless repository&.pending? || repository&.ready? || repository&.pending_retry?

          in_lock(lease_key(id), ttl: LEASE_TTL, sleep_sec: LEASE_TRY_AFTER, retries: LEASE_RETRIES) do
            if repository.pending?
              log_indexing(repository, 'initial') do
                InitialIndexingService.execute(repository)
              end
            elsif repository.pending_retry?
              log_indexing(repository, 'retry_initial') do
                InitialIndexingService.execute(repository)
              end
            elsif repository.ready?
              log_indexing(repository, 'incremental') do
                IncrementalIndexingService.execute(repository)
              end
            end
          end
        rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
          self.class.perform_in(RETRY_IN_IF_LOCKED, id)
        end

        def lease_key(id)
          "#{self.class.name}/#{id}"
        end

        def log_indexing(repository, indexing_mode)
          logger.info(build_structured_payload(
            message: 'Indexing started',
            ai_active_context_code_repository_id: repository.id,
            project_id: repository.project_id,
            enabled_namespace_id: repository.enabled_namespace_id,
            indexing_mode: indexing_mode))

          yield

          logger.info(build_structured_payload(
            message: 'Indexing done',
            ai_active_context_code_repository_id: repository.id,
            project_id: repository.project_id,
            enabled_namespace_id: repository.enabled_namespace_id,
            indexing_mode: indexing_mode))
        end
      end
    end
  end
end
