# frozen_string_literal: true

module Ai
  module Catalog
    module Flows
      class ExecuteCodeConflictAiWorkflowTriggersWorker
        include Ai::CloudEventsFlowTriggerWorker
        include Ai::MergeRequestFlowTriggerFilterData

        concurrency_limit -> { 100 }
        idempotent!

        # RunService links the service account of each trigger to the merge request author, the user of the event.
        # A job of a push by a flow can find the conflict. Without this opt-out, this job gets the link of that flow.
        # If that link has the same service account and another user, RunService raises IdentityLinkMismatchError.
        skip_composite_identity_passthrough!

        class << self
          def cloud_event_class
            MergeRequests::CodeConflictEvent
          end

          def event_type
            :merge_request_code_conflict
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

        # Duo Developer resolves conflicts only with Software Factory enabled. The filter of the flow trigger holds
        # the scope, for example the merge requests that a flow created and that are not drafts. Other flows skip
        # this check.
        def passes_trigger_checks?(flow_trigger, _cloud_event, merge_request, _parent_workflow)
          return true unless flow_trigger.developer_flow?

          reason = developer_skip_reason(merge_request)
          return true unless reason

          logger.info(structured_payload(message: 'Duo Developer does not resolve conflicts on this merge request.',
            reason: reason, flow_trigger_id: flow_trigger.id, merge_request_id: merge_request.id))

          false
        end

        def developer_skip_reason(merge_request)
          return :software_factory_disabled unless ::Gitlab::Ai::SoftwareFactory.enabled?(merge_request.target_project)

          # The event also fires while the merge request is locked, and the job can run after a close or a merge.
          :not_open unless merge_request.opened?
        end
      end
    end
  end
end
