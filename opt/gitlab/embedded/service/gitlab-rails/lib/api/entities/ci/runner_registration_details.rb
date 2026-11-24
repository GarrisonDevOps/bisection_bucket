# frozen_string_literal: true

module API
  module Entities
    module Ci
      class RunnerRegistrationDetails < Grape::Entity
        expose :id, documentation: { type: 'Integer', format: 'int64', example: 1 }
        expose :token, documentation: { type: 'String', example: 'glrt-abc123' }
        expose :token_expires_at, documentation: { type: 'DateTime', example: '2025-01-01T00:00:00.000Z' }
      end
    end
  end
end
