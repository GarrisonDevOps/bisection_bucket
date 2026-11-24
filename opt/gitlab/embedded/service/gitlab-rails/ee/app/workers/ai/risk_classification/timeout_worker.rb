# frozen_string_literal: true

module Ai
  module RiskClassification
    # Shim for jobs queued under the old name. Remove once the queue is empty.
    class TimeoutWorker
      include ApplicationWorker

      data_consistency :delayed
      idempotent!
      defer_on_database_health_signal :gitlab_main, [:merge_requests_risk_assessments]
      feature_category :dap_code_review
      urgency :low

      def perform(*args)
        ::Ai::RiskAssessment::TimeoutWorker.new.perform(*args)
      end
    end
  end
end
