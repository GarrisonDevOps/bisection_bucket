# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      # Join record between a GitLab Duo Agent Platform session and a work item.
      # Exposed from both directions: from a session (Workflow#work_item_links) and
      # from a work item (WorkItem#duo_workflow_links). The matching artifact for the
      # caller's direction is the "other" side of the link.
      class WorkflowWorkItemLinkType < WorkflowLinkBaseType # rubocop: disable Graphql/AuthorizeTypes -- authorization inherited from WorkflowLinkBaseType
        graphql_name 'DuoWorkflowWorkItemLink'
        description 'Link between a GitLab Duo Agent Platform session and a work item.'

        field :link_type, Types::Ai::DuoWorkflows::WorkItemLinkTypeEnum,
          scopes: FIELD_SCOPES,
          null: false, description: 'How the work item relates to the session.'

        field :work_item, ::Types::WorkItemType,
          scopes: FIELD_SCOPES,
          null: true, description: 'Linked work item.'
      end
    end
  end
end
