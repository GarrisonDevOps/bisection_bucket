# frozen_string_literal: true

module API
  module Entities
    module Ci
      module JobRequest
        class Step < Grape::Entity
          expose :name, documentation: { type: 'String' }
          expose :script, documentation: { type: 'String', is_array: true }
          expose :timeout, documentation: { type: 'Integer' }
          expose :when, documentation: { type: 'String' }
          expose :allow_failure, documentation: { type: 'Boolean' }
        end
      end
    end
  end
end
