# frozen_string_literal: true

module Ai
  module ActiveContext
    module Code
      class MarkRepositoryAsPendingDeletionEventWorker
        include Gitlab::EventStore::Subscriber
        include Gitlab::Utils::StrongMemoize
        prepend ::Geo::SkipSecondary

        feature_category :semantic_code_search
        deduplicate :until_executed
        data_consistency :sticky
        urgency :low
        idempotent!
        defer_on_database_health_signal :gitlab_main, [:p_ai_active_context_code_repositories], 10.minutes

        BATCH_SIZE = 2000

        def handle_event(_)
          return false unless Ai::ActiveContext::Collections::Code.indexing?

          process_repositories
        end

        private

        def process_repositories
          remaining = BATCH_SIZE

          remaining -= mark_repositories_as_pending_delete(remaining, :without_enabled_namespace)
          return reemit_event if remaining <= 0

          remaining -= mark_repositories_as_pending_delete(remaining, :duo_features_disabled)
          return reemit_event if remaining <= 0

          mark_repositories_as_pending_delete(remaining, :no_recent_activity)
        end

        def mark_repositories_as_pending_delete(limit, scope_name)
          updated_count = 0

          Ai::ActiveContext::Code::Repository.with_each_partition do |partition|
            break if updated_count >= limit

            updated_count += relation(partition, scope_name)
              .limit(limit - updated_count)
              .mark_as_pending_deletion_with_reason(scope_name.to_s)
          end

          updated_count
        end

        def relation(partition, scope_name)
          base_relation = partition
            .with_active_connection
            .not_in_delete_states

          case scope_name
          when :without_enabled_namespace
            base_relation.without_enabled_namespace
          when :duo_features_disabled
            base_relation.duo_features_disabled
          when :no_recent_activity
            base_relation.no_recent_activity
          else
            raise ArgumentError, "Unknown scope: #{scope_name}"
          end
        end

        def reemit_event
          Gitlab::EventStore.publish(MarkRepositoryAsPendingDeletionEvent.build)
        end
      end
    end
  end
end
