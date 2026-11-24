# frozen_string_literal: true

module API
  module Entities
    module Ci
      class ResetTokenResult < Grape::Entity
        expose(:token, documentation: { type: 'String', example: 'your_runner_token' })
        expose(:token_expires_at,
          documentation: { type: 'DateTime', example: '2025-01-01T00:00:00.000Z' },
          if: ->(object, options) { object.expirable? })
      end
    end
  end
end
