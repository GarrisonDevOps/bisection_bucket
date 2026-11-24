# frozen_string_literal: true

module Gitlab
  module DuoWorkflow
    # Decides whether a consumer reads channel_values from checkpoint_headers and
    # checkpoint_blobs deltas instead of the legacy p_duo_workflows_checkpoints row.
    #
    # Every consumer resolves to #read?, so none can skip
    # incremental_checkpoints_enabled. CreateCheckpointService writes a header only
    # when that column is set, so a gated read always has blobs to fold. That's what
    # makes the header table a safe superset of the legacy one, with no merging.
    class IncrementalBlobGate
      def initialize(workflow)
        @workflow = workflow
      end

      # The __start__ channel read in CreateCheckpointService and the batch header
      # loaders use this gate, which skips the header read; every other reader uses #read?.
      def reconstruct?
        workflow.incremental_checkpoints_enabled?
      end

      # The shared condition behind every consumer gate. The write path stays on
      # #reconstruct?, so a checkpoint write pays no membership query.
      def read?
        reconstruct? && !workflow.legacy_checkpoint_fallback?
      end

      private

      attr_reader :workflow
    end
  end
end
