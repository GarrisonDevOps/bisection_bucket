# frozen_string_literal: true

module Resolvers
  module Ai
    module DuoWorkflows
      class WorkflowNoteLinksResolver < WorkflowLinksBaseResolver
        type Types::Ai::DuoWorkflows::WorkflowNoteLinkType.connection_type, null: true

        self.link_type_enum = Types::Ai::DuoWorkflows::NoteLinkTypeEnum
        self.links_association = :note_links
      end
    end
  end
end
