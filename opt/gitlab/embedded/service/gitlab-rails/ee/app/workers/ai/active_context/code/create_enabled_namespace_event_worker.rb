# frozen_string_literal: true

module Ai
  module ActiveContext
    module Code
      class CreateEnabledNamespaceEventWorker
        include Gitlab::EventStore::Subscriber
        include Gitlab::Utils::StrongMemoize
        prepend ::Geo::SkipSecondary

        feature_category :semantic_code_search
        deduplicate :until_executed
        data_consistency :sticky
        urgency :low
        idempotent!
        defer_on_database_health_signal :gitlab_main,
          [:p_ai_active_context_code_enabled_namespaces, :gitlab_subscriptions],
          10.minutes

        LIMIT = 10_000
        BATCH_SIZE = 1_000

        def handle_event(event)
          return false unless eligible_instance?
          return false unless ::Ai::ActiveContext::Collections::Code.indexing?

          last_processed_id = event.event_data[:last_processed_id]
          process_in_batches!(last_processed_id)
        end

        private

        def eligible_instance?
          return true if gitlab_com

          return false unless ::Gitlab::CurrentSettings.instance_level_ai_beta_features_enabled?
          return false unless ::License.ai_features_available?

          true
        end

        def process_in_batches!(last_processed_id)
          total_count = 0

          relation = if gitlab_com
                       GitlabSubscription.with_active_paid_or_trial_hosted_plan
                     else
                       Namespace.group_namespaces.top_level
                     end

          relation = relation.id_greater_than(last_processed_id) if last_processed_id

          relation.each_batch(of: BATCH_SIZE) do |batch|
            last_id = batch.maximum(:id)

            namespace_ids = if gitlab_com
                              Ai::ActiveContext::Code::EnabledNamespace.valid_saas_namespaces
                                .id_in(batch.pluck(:namespace_id)) # rubocop: disable CodeReuse/ActiveRecord -- avoids double join with select subquery
                                .pluck_primary_key
                            else
                              batch.pluck_primary_key
                            end

            eligible_namespace_ids = namespace_ids - existing_namespace_ids(namespace_ids)

            next if eligible_namespace_ids.empty?

            records_to_insert = eligible_namespace_ids.map do |namespace_id|
              { namespace_id: namespace_id, connection_id: active_connection.id, state: 'ready' }
            end

            Ai::ActiveContext::Code::EnabledNamespace.insert_all(
              records_to_insert,
              unique_by: %w[connection_id namespace_id]
            )

            total_count += records_to_insert.size

            if total_count >= LIMIT
              reemit_event(last_id)
              break
            end
          end

          log_extra_metadata_on_done(:enabled_namespaces_created, total_count)
        end

        def reemit_event(last_processed_id)
          Gitlab::EventStore.publish(CreateEnabledNamespaceEvent.build(last_processed_id: last_processed_id))
        end

        def existing_namespace_ids(namespace_ids)
          active_connection.enabled_namespaces.namespace_id_in(namespace_ids).map(&:namespace_id)
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
