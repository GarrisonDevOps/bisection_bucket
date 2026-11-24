# frozen_string_literal: true

module API
  module Entities
    module Cd
      class Rollout < Grape::Entity
        expose :id, documentation: { type: 'Integer', example: 1 }
        expose :iid, documentation: { type: 'Integer', example: 1 }
        expose :state, documentation: { type: 'String', example: 'in_progress' }
        expose :workflow_ref, documentation: { type: 'String', example: 'cd-rollout-1' }
        expose :started_at, documentation: { type: 'DateTime', example: '2026-07-22T11:37:00Z' }
        expose :finished_at, documentation: { type: 'DateTime', example: '2026-07-22T11:42:00Z' }
      end
    end
  end
end
