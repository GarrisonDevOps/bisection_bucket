# frozen_string_literal: true

module Ai
  module Catalog
    module Flows
      class ExecuteMergeRequestApprovedWorkflowTriggersWorker
        include Ai::CloudEventsFlowTriggerWorker
        include Ai::MergeRequestFlowTriggerFilterData

        concurrency_limit -> { 100 }
        idempotent!

        class << self
          def cloud_event_class
            MergeRequests::ApprovedCloudEvent
          end

          def event_type
            :merge_request
          end

          def action
            'approved'
          end
        end

        private

        def find_resource_and_container(cloud_event)
          merge_request = MergeRequest.find_by_id(cloud_event.event_data[:merge_request_id])

          unless merge_request
            logger.info(structured_payload(message: 'Merge request not found.',
              merge_request_id: cloud_event.event_data[:merge_request_id]))
            return
          end

          [merge_request, merge_request.target_project]
        end

        # Fires only when the MR is fully approved AND the MR's approval is
        # the most recent one (guards against concurrent approvals both firing)
        def passes_event_checks?(cloud_event, merge_request)
          return false unless merge_request.approval_state.approved?

          event_time = Time.zone.parse(cloud_event.event_data[:approved_at])

          latest = merge_request.approvals.maximum(:created_at)
          latest && event_time >= latest
        end
      end
    end
  end
end
