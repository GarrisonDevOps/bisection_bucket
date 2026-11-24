# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class WorkflowWorkItem < ::ApplicationRecord
      include WorkflowLinkable

      self.table_name = :duo_workflows_workflow_work_items

      links_workflow_to :work_item, class_name: 'WorkItem', inverse_of: false

      scope :created_for_work_items_order_by_id_asc, ->(ids) {
        link_type_created.where(work_item_id: ids).order(:id)
      }

      enum :link_type, {
        # the work item the flow was initiated against, e.g. a developer flow
        # started from the work item via the "Implement with GitLab Duo" button.
        source: 0,
        # the work item was created by the flow, e.g. the agent created a new
        # work item via the API (`glab`) while the workflow was running.
        created: 1
      }, prefix: true
    end
  end
end
