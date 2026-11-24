# frozen_string_literal: true

module Resolvers
  module Ai
    module DuoWorkflows
      class WorkItemDuoWorkflowLinksResolver < WorkflowLinksBaseResolver
        type Types::Ai::DuoWorkflows::WorkflowWorkItemLinkType.connection_type, null: true

        self.link_type_enum = Types::Ai::DuoWorkflows::WorkItemLinkTypeEnum
        self.links_association = :duo_workflow_links
      end
    end
  end
end
