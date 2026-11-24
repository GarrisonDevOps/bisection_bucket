# frozen_string_literal: true

# rubocop: disable Cop/DestroyAll -- need to perform destroy_all so that FK cleanup can happen

module Ai
  module ActiveContext
    module Code
      class ProcessInvalidEnabledNamespaceEventWorker
        include Gitlab::EventStore::Subscriber
        include Gitlab::Utils::StrongMemoize
        prepend ::Geo::SkipSecondary

        feature_category :semantic_code_search
        deduplicate :until_executed
        data_consistency :sticky
        urgency :low
        idempotent!
        defer_on_database_health_signal :gitlab_main, [:gitlab_subscriptions], 10.minutes

        LIMIT = 100_000
        BATCH_SIZE = 10_000

        def handle_event(event)
          return false unless ::Ai::ActiveContext::Collections::Code.indexing?
          return false if !gitlab_com && instance_valid?

          last_processed_id = event.event_data[:last_processed_id]
          process_in_batches!(last_processed_id)
        end

        private

        def process_in_batches!(last_processed_id)
          processed_count = 0
          last_id = last_processed_id

          relation = active_connection.enabled_namespaces.ordered_by_id
          relation = relation.id_greater_than(last_processed_id) if last_processed_id

          relation.each_batch(of: BATCH_SIZE) do |batch|
            batch_size = batch.size
            last_id = batch.maximum(:id)

            if gitlab_com
              process_gitlab_com_batch(batch)
            else
              batch.destroy_all
            end

            processed_count += batch_size

            if processed_count >= LIMIT
              reemit_event(last_id)
              break
            end
          end

          log_extra_metadata_on_done(:enabled_namespaces_processed, processed_count)
          log_extra_metadata_on_done(:last_processed_id, last_id) if last_id
        end

        def process_gitlab_com_batch(batch)
          batch_namespace_ids = batch.pluck(:namespace_id) # rubocop: disable CodeReuse/ActiveRecord -- pluck is more performant
          invalid_namespace_ids = batch_namespace_ids - valid_namespace_ids(batch_namespace_ids)

          return if invalid_namespace_ids.blank?

          batch
            .namespace_id_in(invalid_namespace_ids)
            .destroy_all
        end

        def valid_namespace_ids(batch_namespace_ids)
          Ai::ActiveContext::Code::EnabledNamespace
            .valid_saas_namespaces
            .id_in(batch_namespace_ids)
            .pluck_primary_key
        end

        def instance_valid?
          ::Gitlab::CurrentSettings.instance_level_ai_beta_features_enabled? &&
            ::License.ai_features_available?
        end

        def reemit_event(last_processed_id)
          Gitlab::EventStore.publish(ProcessInvalidEnabledNamespaceEvent.build(last_processed_id: last_processed_id))
        end

        def active_connection
          Ai::ActiveContext::Connection.active
        end
        strong_memoize_attr :active_connection

        def gitlab_com
          ::Gitlab::Saas.feature_available?(:duo_chat_on_saas)
        end
        strong_memoize_attr :gitlab_com
      end
    end
  end
end

# rubocop: enable Cop/DestroyAll
