# frozen_string_literal: true

module Search
  module Zoekt
    class SaasRolloutEventWorker
      include Gitlab::EventStore::Subscriber
      include Search::Zoekt::EventWorker
      prepend ::Geo::SkipSecondary

      idempotent!
      defer_on_database_health_signal :gitlab_main, [:zoekt_enabled_namespaces], 10.minutes

      BATCH_SIZE = 2000
      BUFFER_SIZE = 500

      def handle_event(_event)
        return false unless ::Search::Zoekt.licensed_and_indexing_enabled?
        return false unless ::Gitlab::Saas.feature_available?(:exact_code_search)

        indexed_namespaces_ids = Search::Zoekt::EnabledNamespace.find_each.map(&:root_namespace_id).to_set

        processed_count = 0
        buffer = []
        each_eligible_namespace do |namespace|
          next if indexed_namespaces_ids.include?(namespace.id)

          buffer << { root_namespace_id: namespace.id }

          if buffer.size >= BUFFER_SIZE
            processed_count += bulk_insert_namespaces(buffer)
            buffer.clear
          end

          break if processed_count >= BATCH_SIZE
        end

        # Insert any remaining records
        processed_count += bulk_insert_namespaces(buffer) if buffer.any?

        log_extra_metadata_on_done(:enabled_namespaces_count, processed_count)

        reemit_event if processed_count >= BATCH_SIZE
      end

      private

      def each_eligible_namespace
        GitlabSubscription.with_active_paid_or_trial_hosted_plan.each_batch(of: 500) do |batch|
          Namespace.top_level.id_in(batch.select(:namespace_id)).each do |namespace|
            yield namespace
          end
        end
      end

      def bulk_insert_namespaces(values)
        rows = Search::Zoekt::EnabledNamespace.insert_all(
          values,
          unique_by: :root_namespace_id
        )
        rows.count
      end

      def reemit_event
        Gitlab::EventStore.publish(Search::Zoekt::SaasRolloutEvent.new(data: {}))
      end
    end
  end
end
