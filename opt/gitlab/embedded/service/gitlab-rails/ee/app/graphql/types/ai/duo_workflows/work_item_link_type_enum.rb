# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      class WorkItemLinkTypeEnum < BaseEnum
        graphql_name 'DuoWorkflowWorkItemLinkType'
        description 'Type of link between a GitLab Duo Agent Platform session and a work item.'

        from_rails_enum(
          ::Ai::DuoWorkflows::WorkflowWorkItem.link_types,
          description: 'Link of type `%{name}` between a session and a work item.'
        )
      end
    end
  end
end
