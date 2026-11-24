# frozen_string_literal: true

module API
  module Entities
    module Ci
      module JobRequest
        class Artifacts < Grape::Entity
          expose :name, documentation: { type: 'String' }
          expose :untracked, expose_nil: false, documentation: { type: 'Boolean' }
          expose :paths, documentation: { type: 'String', is_array: true }
          expose :exclude, expose_nil: false, documentation: { type: 'String', is_array: true }
          expose :when, documentation: { type: 'String' }
          expose :expire_in, documentation: { type: 'String' }
          expose :artifact_type, documentation: { type: 'String' }
          expose :artifact_format, documentation: { type: 'String' }
        end
      end
    end
  end
end
