# frozen_string_literal: true

module API
  module Entities
    module Ci
      module JobRequest
        class Cache < Grape::Entity
          expose :key, documentation: { type: 'String' }
          expose :untracked, documentation: { type: 'Boolean' }
          expose :paths, documentation: { type: 'String', is_array: true }
          expose :policy, documentation: { type: 'String' }
          expose :when, documentation: { type: 'String' }
          expose :fallback_keys, documentation: { type: 'String', is_array: true }
        end
      end
    end
  end
end
