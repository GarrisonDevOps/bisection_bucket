# frozen_string_literal: true

module API
  module Entities
    module Ai
      module ExternalAgents
        class Session < Grape::Entity
          expose :id, documentation: { type: 'Integer', example: 1 }
          expose :agent_type, documentation: { type: 'String', example: 'claude-code' }
          expose :user_id, documentation: { type: 'Integer', example: 1 }
          expose :status, documentation: { type: 'String', example: 'running' }
          expose :flow_type, documentation: { type: 'String', example: 'external_agent' }
          expose :glab_version, documentation: { type: 'String', example: 'glab 1.121.0 (abc1234)' }
          expose :agent_version, documentation: { type: 'String', example: '2.1.295' }
          expose :sync_type, documentation: { type: 'String', example: 'hook' }
          expose :external_xid, documentation: { type: 'String', example: 'uuid' }
          expose :parent_external_xid, documentation: { type: 'String', example: 'agent-session-1' }
          expose :session_started_at, documentation: { type: 'String', example: '2026-06-17T00:00:00.000Z' }
          expose :session_finished_at, documentation: { type: 'String', example: '2026-06-17T00:00:00.000Z' }
          expose :created_at, documentation: { type: 'String', example: '2026-06-17T00:00:00.000Z' }
          expose :updated_at, documentation: { type: 'String', example: '2026-06-17T00:00:00.000Z' }
        end
      end
    end
  end
end
