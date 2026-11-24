# frozen_string_literal: true

module Ai
  module DapFactory
    # The signal watches notes, which autovacuums often enough that this would defer for reasons
    # unrelated to the single note it reads and writes.
    # rubocop:disable Sidekiq/EnforceDatabaseHealthSignalDeferral -- one note read and at most one write
    class ValidateMergeRequestWorker
      include ApplicationWorker

      data_consistency :sticky
      urgency :low

      deduplicate :until_executed, if_deduplicated: :reschedule_once
      idempotent!

      feature_category :dap_triggers

      def perform(merge_request_id)
        merge_request = MergeRequest.find_by_id(merge_request_id)
        return unless merge_request
        return unless ::Gitlab::Ai::SoftwareFactory.enabled?(merge_request.target_project)

        ValidateMergeRequestService.new(merge_request: merge_request).execute
      end
    end
    # rubocop:enable Sidekiq/EnforceDatabaseHealthSignalDeferral
  end
end
