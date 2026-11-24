# frozen_string_literal: true

module Ai
  module Catalog
    module Flows
      class ExecuteMergeRequestCreatedWorkflowTriggersWorker
        include Ai::CloudEventsFlowTriggerWorker
        include Ai::MergeRequestFlowTriggerFilterData

        concurrency_limit -> { 100 }
        idempotent!

        class << self
          def cloud_event_class
            MergeRequests::AfterCreateCloudEvent
          end

          def event_type
            :merge_request
          end

          # User-facing trigger action, matching the `created` wire event_type of
          # MergeRequests::AfterCreateCloudEvent.
          def action
            'created'
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
      end
    end
  end
end
