# frozen_string_literal: true

module API
  module Entities
    module Orbit
      class Grep < Grape::Entity
        expose :version, documentation: { type: 'String', example: '1.2.0' }
        expose :request, documentation: { type: 'Hash' }
        expose :target, documentation: { type: 'Hash' }
        expose :scopes, documentation: { type: 'Array' }
        expose :results, documentation: { type: 'Array' }
        expose :result_count, documentation: { type: 'Integer', example: 2 }
        expose :truncated, documentation: {
          type: 'Boolean',
          example: false,
          desc: 'Whether the total limit was reached before all scopes were exhausted, ' \
            'or a scope has more results than per_scope'
        }
      end
    end
  end
end
