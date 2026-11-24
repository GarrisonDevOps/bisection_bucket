# frozen_string_literal: true

module Resolvers
  module Ai
    module DuoWorkflows
      class WorkflowPipelineLinksResolver < WorkflowLinksBaseResolver
        type Types::Ai::DuoWorkflows::WorkflowPipelineLinkType.connection_type, null: true

        self.link_type_enum = Types::Ai::DuoWorkflows::PipelineLinkTypeEnum
        self.links_association = :pipeline_links
      end
    end
  end
end
