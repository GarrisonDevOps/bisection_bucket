# frozen_string_literal: true

module Analytics
  module KnowledgeGraph
    class AutoIndexWorker
      include ApplicationWorker
      include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- self-managed instance-wide cron job

      data_consistency :sticky
      feature_category :knowledge_graph
      urgency :low
      deduplicate :until_executed, if_deduplicated: :reschedule_once
      idempotent!
      defer_on_database_health_signal :gitlab_main_org,
        [:knowledge_graph_enabled_namespaces, :knowledge_graph_excluded_namespaces], 10.minutes

      def perform
        return unless ::Analytics::KnowledgeGraph.service_configured?
        return if Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        return unless account.eligible?

        remove_excluded_namespaces
        return unless Gitlab::CurrentSettings.orbit_auto_index_root_namespace?

        enroll_namespaces
      end

      private

      def account
        ::Analytics::Orbit::Billing.instance_account
      end

      def remove_excluded_namespaces
        ExcludedNamespace.each_batch do |scope|
          EnabledNamespace.for_root_namespace_id(scope.select(:root_namespace_id)).delete_all
        end
      end

      def enroll_namespaces
        Group.top_level.each_batch do |batch|
          rows = batch.root_namespaces_without_knowledge_graph_enabled_namespace.pluck_primary_key.map do |id|
            { root_namespace_id: id }
          end
          EnabledNamespace.insert_all(
            rows,
            unique_by: [:root_namespace_id]
          )
          account.record_auto_indexed(rows.map { |row| row[:root_namespace_id] })
        end
      end
    end
  end
end
