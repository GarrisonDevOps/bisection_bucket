# frozen_string_literal: true

module Ai
  module ActiveContext
    class DisableWorker
      include ::ApplicationWorker
      prepend ::Geo::SkipSecondary

      idempotent!
      deduplicate :until_executing, including_scheduled: true
      worker_resource_boundary :cpu
      urgency :low
      data_consistency :sticky
      feature_category :semantic_code_search
      defer_on_database_health_signal :gitlab_main, [:ai_active_context_connections], 10.minutes

      def perform
        connection = ::ActiveContext.adapter&.connection

        return false unless connection

        connection.deactivate!
      end
    end
  end
end
