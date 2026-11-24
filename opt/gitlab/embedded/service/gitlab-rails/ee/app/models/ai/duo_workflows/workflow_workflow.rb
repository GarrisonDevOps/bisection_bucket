# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class WorkflowWorkflow < ::ApplicationRecord
      include WorkflowLinkable

      self.table_name = :duo_workflows_workflow_workflows

      links_workflow_to :linked_workflow, class_name: 'Ai::DuoWorkflows::Workflow', inverse_of: false

      enum :link_type, {
        # the workflow whose restart produced this workflow run
        source: 0
      }, prefix: true

      validate :linked_workflow_is_not_the_workflow

      def self.newest_source_workflow_ids(linked_workflow_ids)
        link_type_source.where(linked_workflow_id: linked_workflow_ids).group(:linked_workflow_id).maximum(:workflow_id)
      end

      private

      def linked_workflow_is_not_the_workflow
        return if workflow_id.blank? || workflow_id != linked_workflow_id

        errors.add(:linked_workflow, 'must be a different workflow')
      end
    end
  end
end
