# frozen_string_literal: true

module Types
  module Ai
    module Governance
      class SessionNoteLinkType < SessionLinkBaseType # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes :read_agent_artifacts
        graphql_name 'AiGovernanceSessionNoteLink'
        description 'Link between an AI governance session and a note.'

        PRELOADS = [:author, :noteable, { project: [:project_feature, :route, { namespace: :route }] }].freeze

        field :link_type, ::Types::Ai::DuoWorkflows::NoteLinkTypeEnum,
          null: false,
          description: 'How the note relates to the session.'

        field :note, ::Types::Notes::NoteType,
          null: true,
          description: 'Linked note. Null when the current user cannot read the note.'

        def note
          ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Note, object.note_id, PRELOADS).find
        end
      end
    end
  end
end
