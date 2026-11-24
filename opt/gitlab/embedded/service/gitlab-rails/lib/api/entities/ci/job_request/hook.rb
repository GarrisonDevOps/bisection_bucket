# frozen_string_literal: true

module API
  module Entities
    module Ci
      module JobRequest
        class Hook < Grape::Entity
          expose :name, documentation: { type: 'String' }
          expose :script, documentation: { type: 'String', is_array: true }
        end
      end
    end
  end
end
