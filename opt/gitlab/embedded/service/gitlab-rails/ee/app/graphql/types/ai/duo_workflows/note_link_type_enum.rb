# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      class NoteLinkTypeEnum < BaseEnum
        graphql_name 'DuoWorkflowNoteLinkType'
        description 'Type of link between a GitLab Duo Agent Platform session and a note.'

        from_rails_enum(
          ::Ai::DuoWorkflows::WorkflowNote.link_types,
          description: 'Link of type `%{name}` between a session and a note.'
        )
      end
    end
  end
end
