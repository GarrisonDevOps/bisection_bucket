# frozen_string_literal: true

module API
  module Entities
    module Ai
      module DuoWorkflows
        class Checkpoint < BasicCheckpoint
          expose :checkpoint, if: ->(object) { object.compressed_checkpoint.blank? }, documentation: { type: 'JSON' }
          expose :compressed_checkpoint, documentation: { type: 'String' },
            if: ->(object) { object.compressed_checkpoint.present? }
          expose :checkpoint_writes, using: ::API::Entities::Ai::DuoWorkflows::CheckpointWrite,
            documentation: { is_array: true }
          expose :current_thread, documentation: { type: 'Integer' }
          expose :metadata, documentation: { type: 'JSON' }
        end
      end
    end
  end
end
