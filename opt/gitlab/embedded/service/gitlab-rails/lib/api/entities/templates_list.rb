# frozen_string_literal: true

module API
  module Entities
    class TemplatesList < Grape::Entity
      expose :key, documentation: { type: 'String', example: 'mit', desc: 'Key of the template.' }
      expose :name, documentation: { type: 'String', example: 'MIT License', desc: 'Name of the template.' }
    end
  end
end
