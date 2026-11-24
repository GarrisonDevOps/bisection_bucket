# frozen_string_literal: true

module API
  module Entities
    module Ai
      module ExternalAgents
        class Identity < Grape::Entity
          expose :id, documentation: { type: 'Integer', example: 1 }
          expose :agent_type, documentation: { type: 'String', example: 'claude-code' }
          expose :revoked_at, documentation: { type: 'String', example: nil }
          expose :created_at, documentation: { type: 'String', example: '2026-06-17T00:00:00.000Z' }
        end
      end
    end
  end
end
