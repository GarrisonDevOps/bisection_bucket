# frozen_string_literal: true

module Security
  module Scans
    class IngestReportsWorker
      include ApplicationWorker
      include Gitlab::EventStore::Subscriber

      feature_category :vulnerability_management
      urgency :low
      worker_resource_boundary :cpu
      data_consistency :sticky

      defer_on_database_health_signal :gitlab_sec, [::Vulnerabilities::Finding.table_name], 1.minute
      idempotent!

      def handle_event(event)
        build = ::Ci::Build.find_by_id(event.data[:job_id])
        return unless build

        ::Security::Scans::IngestReportsService.execute(build.pipeline)
      end
    end
  end
end
