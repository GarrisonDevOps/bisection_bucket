# frozen_string_literal: true

module API
  module Entities
    class Suggestion < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64', example: 1, desc: 'ID of the suggestion.' }
      expose :from_line, documentation: { type: 'Integer', example: 1, desc: 'First line number of the suggestion.' }
      expose :to_line, documentation: { type: 'Integer', example: 1, desc: 'Last line number of the suggestion.' }
      expose :appliable?, as: :appliable,
        documentation: { type: 'Boolean', example: true, desc: 'If `true`, the suggestion can be applied.' }
      expose :applied,
        documentation: { type: 'Boolean', example: false, desc: 'If `true`, the suggestion has been applied.' }
      expose :from_content,
        documentation: { type: 'String', example: "Original content\n",
                         desc: 'Original content before the suggestion.' }
      expose :to_content,
        documentation: { type: 'String', example: "New content\n",
                         desc: 'Suggested content that replaces the original.' }
    end
  end
end
