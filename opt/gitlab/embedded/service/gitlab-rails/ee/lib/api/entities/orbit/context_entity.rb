# frozen_string_literal: true

module API
  module Entities
    module Orbit
      class ContextEntity < Grape::Entity
        expose :token, documentation: { type: 'String', example: 'MergeRequest[123]' }
        expose :resolved_token, expose_nil: false, documentation: { type: 'String', example: 'MergeRequest[123]' }
        expose :type, documentation: { type: 'String', example: 'MergeRequest' }
        expose :id, documentation: { type: 'String', example: '123' }
        expose :found, documentation: { type: 'Boolean' }
        expose :summary, expose_nil: false, documentation: { type: 'Hash' }
        expose :error, expose_nil: false, documentation: { type: 'Hash' }
        expose :expansion, documentation: { type: 'Hash' }
      end
    end
  end
end
