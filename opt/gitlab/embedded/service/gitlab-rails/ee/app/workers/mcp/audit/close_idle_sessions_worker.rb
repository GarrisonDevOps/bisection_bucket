# frozen_string_literal: true

module Mcp
  module Audit
    class CloseIdleSessionsWorker
      include ApplicationWorker
      # rubocop:disable Scalability/CronWorkerContext -- sweeps lapsed sessions across every
      # namespace, so there is no single project, namespace or user to attribute the run to
      include CronjobQueue

      # rubocop:enable Scalability/CronWorkerContext

      idempotent!
      data_consistency :sticky
      feature_category :audit_events
      urgency :low
      defer_on_database_health_signal :gitlab_main_org, [:ai_governance_sessions]

      def perform
        ::Mcp::Audit::CloseIdleSessionsService.new.execute
      end
    end
  end
end
