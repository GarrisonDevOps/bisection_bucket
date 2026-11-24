# frozen_string_literal: true

module API
  module Entities
    class Contributor < Grape::Entity
      expose :name, documentation: { type: 'String', example: 'John Doe', desc: 'Name of the contributor.' }
      expose :email, documentation: {
        type: 'String', example: 'johndoe@example.com', desc: 'Email address of the contributor.'
      }
      expose :commits, documentation: { type: 'Integer', example: 117, desc: 'Number of commits by the contributor.' }
      expose :additions, documentation: {
        type: 'Integer', example: 3, desc: 'Number of lines added by the contributor.'
      }
      expose :deletions, documentation: {
        type: 'Integer', example: 5, desc: 'Number of lines deleted by the contributor.'
      }
    end
  end
end
