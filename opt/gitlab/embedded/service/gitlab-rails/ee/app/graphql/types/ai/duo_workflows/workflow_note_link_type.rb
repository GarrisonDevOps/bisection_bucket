# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      # Join record between a GitLab Duo Agent Platform session and a note.
      # Exposed from both directions: from a session (Workflow#note_links) and
      # from a note (Note#duo_workflow_links). The matching artifact for the
      # caller's direction is the "other" side of the link.
      class WorkflowNoteLinkType < WorkflowLinkBaseType # rubocop: disable Graphql/AuthorizeTypes -- authorization inherited from WorkflowLinkBaseType
        graphql_name 'DuoWorkflowNoteLink'
        description 'Link between a GitLab Duo Agent Platform session and a note.'

        field :link_type, Types::Ai::DuoWorkflows::NoteLinkTypeEnum,
          scopes: FIELD_SCOPES,
          null: false, description: 'How the note relates to the session.'

        field :note, ::Types::Notes::NoteType,
          scopes: FIELD_SCOPES,
          null: true, description: 'Linked note.'
      end
    end
  end
end
