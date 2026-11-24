# frozen_string_literal: true

module API
  module Entities
    module Ci
      class RunnerControllerToken < Grape::Entity
        expose :id, documentation: {
          type: 'Integer', format: 'int64', example: 1,
          desc: 'ID of the runner controller token.'
        }
        expose :runner_controller_id, documentation: {
          type: 'Integer', format: 'int64', example: 1,
          desc: 'ID of the associated runner controller.'
        }
        expose :description, documentation: {
          type: 'String', example: 'Controller for managing runner',
          desc: 'Description of the token.'
        }
        expose :last_used_at, documentation: { type: 'DateTime', desc: 'Date and time when the token was last used.' }
        expose :created_at, documentation: { type: 'DateTime', desc: 'Date and time when the token was created.' }
        expose :updated_at, documentation: { type: 'DateTime', desc: 'Date and time when the token was last updated.' }
      end
    end
  end
end
