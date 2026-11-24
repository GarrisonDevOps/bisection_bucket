# frozen_string_literal: true

module API
  module Entities
    module Ci
      class RunnerControllerInstanceLevelScoping < Grape::Entity
        expose :created_at, documentation: { type: 'DateTime', desc: 'Date and time when the scope was created.' }
        expose :updated_at, documentation: { type: 'DateTime', desc: 'Date and time when the scope was last updated.' }
      end
    end
  end
end
