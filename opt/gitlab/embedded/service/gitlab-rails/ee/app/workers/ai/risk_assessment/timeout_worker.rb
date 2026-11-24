# frozen_string_literal: true

module Ai
  module RiskAssessment
    # No-op: session lifecycle hooks fail abandoned assessments now. Remove in
    # https://gitlab.com/gitlab-org/gitlab/-/work_items/632403.
    class TimeoutWorker
      include ApplicationWorker

      data_consistency :delayed
      idempotent!
      defer_on_database_health_signal :gitlab_main, [:merge_requests_risk_assessments]
      feature_category :dap_code_review
      urgency :low

      def perform(*); end
    end
  end
end
