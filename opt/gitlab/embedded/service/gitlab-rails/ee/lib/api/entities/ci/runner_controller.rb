# frozen_string_literal: true

module API
  module Entities
    module Ci
      class RunnerController < Grape::Entity
        expose :id, documentation: {
          type: 'Integer', format: 'int64', example: 1,
          desc: 'ID of the runner controller.'
        }
        expose :description, documentation: {
          type: 'String', example: 'Controller for managing runner',
          desc: 'Description of the runner controller.'
        }
        expose :state, documentation: {
          type: 'String', example: 'enabled',
          desc: 'State of the runner controller. Possible values: `disabled` (default), `enabled`, or `dry_run`.'
        }
        expose :created_at, documentation: {
          type: 'DateTime',
          desc: 'Date and time when the runner controller was created.'
        }
        expose :updated_at, documentation: {
          type: 'DateTime',
          desc: 'Date and time when the runner controller was last updated.'
        }
      end
    end
  end
end
