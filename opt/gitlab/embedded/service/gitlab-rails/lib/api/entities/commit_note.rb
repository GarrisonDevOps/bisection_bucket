# frozen_string_literal: true

module API
  module Entities
    class CommitNote < Grape::Entity
      expose :note, documentation: {
        type: 'String', example: 'this doc is really nice', desc: 'Content of the comment.'
      }

      expose :path, documentation: {
        type: 'String', example: 'README.md', desc: 'Path of the file the comment is on, relative to the repository.'
      } do |note|
        note.diff_file.try(:file_path) if note.diff_note?
      end

      expose :line, documentation: { type: 'Integer', example: 11, desc: 'Line number the comment is on.' } do |note|
        note.diff_line.try(:line) if note.diff_note?
      end

      expose :line_type, documentation: {
        type: 'String', example: 'new', desc: 'Type of the line the comment is on, such as `new` or `old`.'
      } do |note|
        note.diff_line.try(:type) if note.diff_note?
      end

      expose :author, using: ::API::Entities::UserBasic, documentation: {
        type: '::API::Entities::UserBasic', desc: 'Author of the comment.'
      }
      expose :created_at, documentation: {
        type: 'DateTime', example: '2016-01-19T09:44:55.600Z', desc: 'Date and time when the comment was created.'
      }
    end
  end
end
