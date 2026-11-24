# frozen_string_literal: true

module Ai
  module ActiveContext
    class ConnectionCleanupWorker
      include ::ApplicationWorker
      prepend ::Geo::SkipSecondary

      idempotent!
      deduplicate :until_executing
      worker_resource_boundary :cpu
      urgency :low
      data_consistency :sticky
      feature_category :semantic_code_search
      defer_on_database_health_signal :gitlab_main, [:ai_active_context_connections], 10.minutes

      def perform(connection_id)
        connection = ::Ai::ActiveContext::Connection.find_by_id(connection_id)

        return unless connection
        return if connection.active?

        drop_collections(connection)
        connection.destroy!
      end

      private

      def drop_collections(connection)
        adapter = connection.adapter
        return unless adapter

        begin
          connection.collections.each do |collection|
            adapter.executor.drop_collection(collection.name_without_prefix)
          end
        ensure
          adapter.client.close
        end
      end
    end
  end
end
