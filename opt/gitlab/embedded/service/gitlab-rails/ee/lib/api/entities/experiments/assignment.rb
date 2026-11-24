# frozen_string_literal: true

module API
  module Entities
    module Experiments
      class Assignment < Grape::Entity
        expose :experiment, documentation: { type: 'String', example: 'lightweight_trial_registration_redesign' }
        expose :variant, documentation: { type: 'String', example: 'candidate' }
        expose :context_key, documentation: { type: 'String', example: 'abc123def456' }
        expose :cached, documentation: { type: 'Boolean', example: true }
      end
    end
  end
end
