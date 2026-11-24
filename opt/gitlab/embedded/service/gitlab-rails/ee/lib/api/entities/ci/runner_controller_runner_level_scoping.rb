# frozen_string_literal: true

module API
  module Entities
    module Ci
      class RunnerControllerRunnerLevelScoping < Grape::Entity
        expose :runner_id, documentation: { type: 'Integer', format: 'int64', desc: 'ID of the runner.' }
        expose :created_at, documentation: { type: 'DateTime', desc: 'Date and time when the scope was created.' }
        expose :updated_at, documentation: { type: 'DateTime', desc: 'Date and time when the scope was last updated.' }
      end
    end
  end
end
