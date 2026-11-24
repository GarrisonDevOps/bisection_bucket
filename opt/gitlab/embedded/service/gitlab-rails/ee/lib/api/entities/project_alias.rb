# frozen_string_literal: true

module API
  module Entities
    class ProjectAlias < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64', example: 1, desc: 'ID of the project alias.' }
      expose :project_id, documentation: {
        type: 'Integer', format: 'int64', example: 1, desc: 'ID of the associated project.'
      }
      expose :name, documentation: { type: 'String', example: 'gitlab', desc: 'Name of the alias.' }
    end
  end
end
