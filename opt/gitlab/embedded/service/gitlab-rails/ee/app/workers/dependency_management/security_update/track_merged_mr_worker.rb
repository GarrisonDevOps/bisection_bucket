# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    class TrackMergedMrWorker
      include TracksAutoRemediationMrEvent

      idempotent!

      EVENT_NAME = 'merge_dependency_management_auto_remediation_mr'

      private

      def remediation_state_for(_merge_request)
        :merged
      end
    end
  end
end
