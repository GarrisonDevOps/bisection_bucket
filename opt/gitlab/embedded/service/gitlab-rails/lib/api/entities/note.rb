# frozen_string_literal: true

module API
  module Entities
    class Note < Grape::Entity
      # Only Issue and MergeRequest have iid
      NOTEABLE_TYPES_WITH_IID = %w[Issue MergeRequest].freeze

      expose :id, documentation: { type: 'Integer', format: 'int64', example: 1, desc: 'ID of the note.' }
      expose :type, documentation: {
        type: 'String', example: 'DiscussionNote',
        desc: 'Type of the note, such as `DiscussionNote` or `DiffNote`. `null` for a plain note.'
      }

      expose :body, documentation: { type: 'String', example: 'Note body.', desc: 'Content of the note.' } do |note|
        NotePresenter.new(note, current_user: options[:current_user]).note
      end

      expose :author, using: ::API::Entities::UserBasic,
        documentation: { type: '::API::Entities::UserBasic', desc: 'Author of the note.' }
      expose :created_at,
        documentation: { type: 'DateTime', example: '2022-01-31T15:10:44.988Z',
                         desc: 'Date and time when the note was created.' }
      expose :updated_at,
        documentation: { type: 'DateTime', example: '2022-01-31T15:10:44.988Z',
                         desc: 'Date and time when the note was last updated.' }
      expose :system?, as: :system,
        documentation: { type: 'Boolean', example: false, desc: 'If `true`, the note is a system note.' }
      expose :noteable_id,
        documentation: { type: 'Integer', format: 'int64', example: 1,
                         desc: 'ID of the object the note belongs to, such as an issue or merge request.' }
      expose :noteable_type,
        documentation: { type: 'String', example: 'Issue',
                         desc: 'Type of the object the note belongs to, such as `Issue` or `MergeRequest`.' }
      expose :project_id,
        documentation: { type: 'Integer', format: 'int64', example: 1, desc: 'ID of the project the note belongs to.' }
      expose :commit_id, documentation: { type: 'String', example: '7b09ce7e6f80347baf0316c8c94cdba9a0a7e91d' },
        if: ->(note, _options) { note.noteable_type == "MergeRequest" && note.is_a?(DiffNote) }

      expose :position,
        documentation: { type: 'Hash', desc: 'Position of the note in the diff. Returned only for diff notes.' },
        if: ->(note, _options) { note.is_a?(DiffNote) } do |note|
        note.position.to_h.except(:ignore_whitespace_change)
      end

      expose :resolvable?, as: :resolvable,
        documentation: { type: 'Boolean', example: false, desc: 'If `true`, the note can be resolved.' }
      expose :resolved?, as: :resolved,
        documentation: { type: 'Boolean', example: false,
                         desc: 'If `true`, the note is resolved. Returned only for resolvable notes.' },
        if: ->(note, _options) { note.resolvable? }
      expose :resolved_by, using: ::API::Entities::UserBasic,
        documentation: { type: '::API::Entities::UserBasic',
                         desc: 'User who resolved the note. Returned only for resolvable notes.' },
        if: ->(note, _options) { note.resolvable? }
      expose :resolved_at,
        documentation: { type: 'DateTime', example: '2022-01-31T15:10:44.988Z',
                         desc: 'Date and time when the note was resolved. Returned only for resolvable notes.' },
        if: ->(note, _options) { note.resolvable? }

      expose :suggestions,
        if: ->(note, _options) { note.noteable_type == "MergeRequest" && note.is_a?(DiffNote) },
        using: ::API::Entities::Suggestion,
        documentation: { type: '::API::Entities::Suggestion', is_array: true,
                         desc: 'Suggestions in the note. Returned only for diff notes on merge requests.' }

      expose :confidential?, as: :confidential, documentation: { type: 'Boolean', example: false }
      expose :confidential?, as: :internal, documentation: { type: 'Boolean', example: false }
      expose :imported?, as: :imported, documentation: { type: 'Boolean', example: false }
      expose :imported_from, documentation: { type: 'String', example: 'github' }

      # Avoid N+1 queries as much as possible
      expose(:noteable_iid, documentation: { type: 'Integer', example: 1 }) do |note|
        note.noteable.iid if NOTEABLE_TYPES_WITH_IID.include?(note.noteable_type)
      end

      expose(:commands_changes, documentation: { type: 'Hash' }) { |note| note.commands_changes || {} }
    end

    # To be returned if the note was command-only
    class NoteCommands < Grape::Entity
      expose(:commands_changes, documentation: { type: 'Hash' }) { |note| note.commands_changes || {} }
      expose(:summary, documentation: { type: 'String', is_array: true }) { |note| note.quick_actions_status.messages }
    end
  end
end
