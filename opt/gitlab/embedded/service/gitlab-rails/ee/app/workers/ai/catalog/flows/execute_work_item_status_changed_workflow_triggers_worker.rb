# frozen_string_literal: true

module Ai
  module Catalog
    module Flows
      class ExecuteWorkItemStatusChangedWorkflowTriggersWorker
        include Ai::CloudEventsFlowTriggerWorker

        concurrency_limit -> { 100 }
        idempotent!

        class << self
          def cloud_event_class
            ::WorkItems::StatusChangedEvent
          end

          def event_type
            :work_item
          end

          def action
            'status_changed'
          end
        end

        private

        # Lets `status.name` filter rules match the status the work item moved to, and
        # `work_item_type_id` rules match the type of the work item when the event happened.
        # The CE event does not carry the EE Software Factory marker, so the job reads it from the work item.
        def filter_data_extras(cloud_event, resource)
          {
            'status' => { 'name' => cloud_event.event_data.dig(:status, :name) },
            'work_item_type_id' => cloud_event.event_data[:work_item_type_id],
            'software_factory_enabled' => resource.ai_planning_enabled?
          }
        end

        # Lets goal templates name the user who changed the status. `handle_event` returns
        # early when the event has no user, so it is present here.
        def additional_run_params(cloud_event, _resource)
          { triggered_by_username: cloud_event.current_user.username }
        end

        def find_resource_and_container(cloud_event)
          work_item = WorkItem.find_by_id(cloud_event.event_data[:work_item_id])

          unless work_item
            logger.info(structured_payload(message: 'Work item not found.',
              work_item_id: cloud_event.event_data[:work_item_id]))
            return
          end

          project = work_item.project

          unless project
            logger.info(structured_payload(message: 'Work item has no project, skipping.',
              work_item_id: work_item.id))
            return
          end

          [work_item, project]
        end
      end
    end
  end
end
