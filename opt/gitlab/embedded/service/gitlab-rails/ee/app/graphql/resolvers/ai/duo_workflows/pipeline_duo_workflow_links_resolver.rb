# frozen_string_literal: true

module Resolvers
  module Ai
    module DuoWorkflows
      class PipelineDuoWorkflowLinksResolver < WorkflowLinksBaseResolver
        type Types::Ai::DuoWorkflows::WorkflowPipelineLinkType.connection_type, null: true

        self.link_type_enum = Types::Ai::DuoWorkflows::PipelineLinkTypeEnum
        self.links_association = :duo_workflow_links
      end
    end
  end
end
