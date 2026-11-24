# frozen_string_literal: true

module API
  module Entities
    module Ai
      module DuoWorkflows
        class CheckpointWrite < Grape::Entity
          expose :id, documentation: { type: 'Integer' }
          expose :thread_ts, documentation: { type: 'String' }
          expose :task, documentation: { type: 'String' }
          expose :idx, documentation: { type: 'Integer' }
          expose :channel, documentation: { type: 'String' }
          expose :write_type, documentation: { type: 'String' }
          expose :data, documentation: { type: 'String' }
        end
      end
    end
  end
end
