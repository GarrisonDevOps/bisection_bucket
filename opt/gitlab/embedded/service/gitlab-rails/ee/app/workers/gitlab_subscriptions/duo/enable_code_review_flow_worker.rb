# frozen_string_literal: true

module GitlabSubscriptions
  module Duo
    class EnableCodeReviewFlowWorker
      include ApplicationWorker

      deduplicate :until_executed
      data_consistency :always # rubocop:disable SidekiqLoadBalancing/WorkerDataConsistency -- need most up-to-date data
      idempotent!
      urgency :high
      feature_category :dap_code_review

      def perform(namespace_id)
        namespace = Namespace.find_by_id(namespace_id)

        GitlabSubscriptions::Duo::EnableCodeReviewFlowService.new(namespace: namespace).execute if namespace
      end
    end
  end
end
