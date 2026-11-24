# frozen_string_literal: true

module Ai
  module Catalog
    module Flows
      class ExecuteMergeRequestMergedWorkflowTriggersWorker
        include Ai::CloudEventsFlowTriggerWorker
        include Ai::MergeRequestFlowTriggerFilterData

        concurrency_limit -> { 100 }
        idempotent!

        SESSION_IDS_LIMIT = 20

        class << self
          def cloud_event_class
            MergeRequests::MergedCloudEvent
          end

          def event_type
            :merge_request
          end

          def action
            'merged'
          end
        end

        private

        def find_resource_and_container(cloud_event)
          merge_request_id = cloud_event.event_data[:merge_request_id]
          merge_request = MergeRequest.find_by_id(merge_request_id)

          unless merge_request
            logger.info(structured_payload(message: 'Merge request not found.',
              merge_request_id: merge_request_id))
            return
          end

          [merge_request, merge_request.target_project]
        end

        # Only Duo Developer distills memory when a merge request merges, so only its trigger checks the memory
        # distillation flag. Other flows skip this check.
        def passes_trigger_checks?(flow_trigger, _cloud_event, merge_request, _parent_workflow)
          return true unless flow_trigger.developer_flow?
          return true if Feature.enabled?(:merge_request_merged_memory_distillation, merge_request.target_project)

          logger.info(structured_payload(message: 'Duo Developer does not distill memory for this merge request.',
            reason: :memory_distillation_disabled,
            flow_trigger_id: flow_trigger.id,
            merge_request_id: merge_request.id))

          false
        end

        # The distillation session acts on behalf of the merge request author,
        # not the user who merged it, so attribution lands on the author.
        def resolve_current_user(_cloud_event, merge_request)
          merge_request.author
        end

        def passes_event_checks?(_cloud_event, merge_request)
          return true if developer_session_ids(merge_request).any?

          logger.info(structured_payload(
            message: 'No existing Developer flow session for the merge request.',
            merge_request_id: merge_request.id))

          false
        end

        def developer_session_ids(merge_request)
          @developer_session_ids ||= {}
          @developer_session_ids[merge_request.id] ||= begin
            definition = ::Ai::Catalog::FoundationalFlow.developer_v1.reference

            # Sessions initiated against this MR (merge_request_id FK), capped to avoid unbounded growth.
            direct_ids = ::Ai::DuoWorkflows::Workflow
              .for_merge_request(merge_request)
              .with_workflow_definition(definition)
              .ordered_by_id_desc
              .limit(SESSION_IDS_LIMIT)
              .pluck_primary_key

            # Sessions that created this MR (linked via WorkflowMergeRequest).
            # Always included so the creator session is never pushed out by newer related sessions.
            creator_ids = ::Ai::DuoWorkflows::Workflow
              .with_created_merge_request(merge_request)
              .with_workflow_definition(definition)
              .pluck_primary_key

            (creator_ids + direct_ids).uniq
          end
        end

        def additional_run_params(_cloud_event, merge_request)
          { session_ids: developer_session_ids(merge_request) }
        end
      end
    end
  end
end
