# frozen_string_literal: true

module Resolvers
  module Ai
    module DuoWorkflows
      class WorkflowWorkItemLinksResolver < WorkflowLinksBaseResolver
        type Types::Ai::DuoWorkflows::WorkflowWorkItemLinkType.connection_type, null: true

        self.link_type_enum = Types::Ai::DuoWorkflows::WorkItemLinkTypeEnum
        self.links_association = :work_item_links
      end
    end
  end
end
