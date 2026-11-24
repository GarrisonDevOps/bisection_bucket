# frozen_string_literal: true

module API
  module Entities
    class Template < Grape::Entity
      expose :name, documentation: { type: 'String', example: 'Ruby', desc: 'Name of the template.' }
      expose :content,
        documentation: { type: 'String', example: '# Ruby gitignore template', desc: 'Content of the template.' }
    end
  end
end
