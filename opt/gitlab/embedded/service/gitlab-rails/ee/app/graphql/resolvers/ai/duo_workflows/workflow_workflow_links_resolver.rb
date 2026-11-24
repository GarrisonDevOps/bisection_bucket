# frozen_string_literal: true

module Resolvers
  module Ai
    module DuoWorkflows
      class WorkflowWorkflowLinksResolver < WorkflowLinksBaseResolver
        type Types::Ai::DuoWorkflows::WorkflowWorkflowLinkType.connection_type, null: true

        self.link_type_enum = Types::Ai::DuoWorkflows::WorkflowWorkflowLinkTypeEnum
        self.links_association = :workflow_links
      end
    end
  end
end
