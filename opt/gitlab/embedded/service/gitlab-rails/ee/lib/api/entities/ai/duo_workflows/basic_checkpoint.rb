# frozen_string_literal: true

module API
  module Entities
    module Ai
      module DuoWorkflows
        class BasicCheckpoint < Grape::Entity
          expose :id, documentation: { type: 'Integer' } do |checkpoint|
            checkpoint.id.first
          end
          expose :thread_ts, documentation: { type: 'String' }
          expose :parent_ts, documentation: { type: 'String' }
          expose :checkpoint_ns, documentation: { type: 'String' }
        end
      end
    end
  end
end
