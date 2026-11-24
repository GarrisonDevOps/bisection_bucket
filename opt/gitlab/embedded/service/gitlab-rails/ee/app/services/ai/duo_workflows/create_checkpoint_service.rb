# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class CreateCheckpointService
      include ::Services::ReturnServiceResponses

      def initialize(workflow:, params:)
        @params = params
        @workflow = workflow
      end

      def execute
        is_first_checkpoint = first_checkpoint?
        checkpoint = nil

        ApplicationRecord.transaction do
          # Detached instance (not `@workflow.checkpoints.new`): incremental-only
          # leaves it unsaved, and a later `@workflow.update!` would autosave the
          # association and write the legacy row anyway. Mirrors headers and blobs.
          checkpoint = ::Ai::DuoWorkflows::Checkpoint.new(checkpoint_attributes)

          # Incremental workflows skip the legacy full row but still validate, so a
          # bad payload 400s instead of writing a header for a broken checkpoint.
          if incremental_checkpoints_enabled?
            raise ActiveRecord::Rollback unless checkpoint.valid?
          else
            raise ActiveRecord::Rollback unless checkpoint.save
          end

          write_checkpoint_header(checkpoint) if incremental_checkpoints_enabled?

          if incremental_checkpoints_enabled? && channel_blobs_params.present?
            blobs = build_blobs_batch(checkpoint)
            # unique_by targets the dedup index; without it the conflict target
            # defaults to the composite PK, whose trigger-assigned id never collides.
            @workflow.checkpoint_blobs.bulk_insert!(
              blobs, skip_duplicates: true, unique_by: :idx_duo_wf_checkpoint_blobs_dedup
            )
          end
        end

        return error(checkpoint.errors.full_messages, :bad_request) unless checkpoint_written?(checkpoint)

        # `persist_workflow_updates` bumps updated_at itself when it writes, so the
        # touch only runs when it wrote nothing. Avoids two UPDATEs on the same row.
        wrote_attributes = persist_workflow_updates(checkpoint, first_checkpoint: is_first_checkpoint)
        touch_workflow_for_incremental_only unless wrote_attributes

        publish_checkpoint(checkpoint)
        enqueue_messaging_progress_delivery
        success(checkpoint: checkpoint)
      rescue ActiveRecord::RecordInvalid, ActiveRecord::StatementInvalid, ArgumentError => e
        # ArgumentError covers payloads the gateway should not send: malformed base64
        # `data`, or more channels than the header can record. Return 400, not 500.
        error(e.message, :bad_request)
      end

      def persist_workflow_updates(checkpoint, first_checkpoint:)
        attributes = workflow_attributes_to_update(checkpoint, first_checkpoint: first_checkpoint)
        return if attributes.empty?

        @workflow.update!(attributes)

        regenerate_title

        true
      end

      private

      def workflow_attributes_to_update(checkpoint, first_checkpoint:)
        model_metadata_json = @params[:model_metadata_json]

        if first_checkpoint
          return {
            goal: workflow_goal(checkpoint),
            model_metadata_json: model_metadata_json,
            flow_metadata_json: ::Ai::DuoWorkflows::FlowMetadata.narrowed(
              @workflow.flow_metadata_json, @params[:flow_metadata_json]
            )
          }.compact_blank
        end

        return {} if model_metadata_json.blank? || model_metadata_json == @workflow.model_metadata_json

        { model_metadata_json: model_metadata_json }
      end

      # CLI pre-creates the session with a blank goal, so the title worker enqueued
      # at creation exited early. Re-enqueue only on the blank-to-present transition.
      def regenerate_title
        return unless @workflow.goal_before_last_save.blank? && @workflow.goal.present?

        ::Ai::DuoWorkflows::GenerateWorkflowTitleWorker.perform_async(@workflow.id)
      end

      # Incremental-only skips `checkpoint.save`, so Checkpoint's
      # `after_save :touch_workflow` never fires. CleanStuckWorkflowsService reads
      # `updated_at`, and would force-fail a healthy long-running flow without it.
      def touch_workflow_for_incremental_only
        return unless incremental_checkpoints_enabled?

        @workflow.touch
      rescue ActiveRecord::StatementInvalid => e
        # The header and blobs are already committed, so a lock conflict on the
        # workflow row must not turn a durable write into a 400. The next
        # checkpoint touches it again seconds later.
        ::Gitlab::ErrorTracking.track_exception(e, workflow_id: @workflow.id)
      end

      # Backfills a pre-created workflow's blank goal from the first checkpoint.
      # Web sets it at `__start__.goal`; a CLI-created session carries it at
      # `__start__.context.goal` instead, so fall back to that.
      def workflow_goal(checkpoint)
        start_channel = start_channel_values(checkpoint)
        goal = start_channel['goal'].presence || start_channel.dig('context', 'goal')
        return if goal.blank?

        # Cut by bytes too: a char-only cut leaves a multibyte goal over
        # GOAL_MAX_BYTESIZE, and update! would 500 on the validation.
        goal.truncate(Workflow::GOAL_MAX_LENGTH, omission: '')
            .truncate_bytes(Workflow::GOAL_MAX_BYTESIZE, omission: '')
      end

      # The goal lives in the `__start__` channel. Under the blob read gate the
      # channel's blob wins, because incremental-only payloads carry no
      # channel_values; the payload is the fallback for a gateway old enough to
      # send no blobs.
      def start_channel_values(checkpoint)
        from_blobs = @workflow.incremental_blob_gate.reconstruct? ? start_channel_from_blobs : {}
        return from_blobs if from_blobs.present?

        from_checkpoint = channel_values(checkpoint)&.dig('__start__')
        from_checkpoint.is_a?(Hash) ? from_checkpoint : {}
      end

      def start_channel_from_blobs
        blob = channel_blobs_params&.find { |attrs| attrs[:channel] == '__start__' }
        return {} unless blob

        value = ::Gitlab::DuoWorkflow::ChannelValuesReconstructor.decode(Base64.strict_decode64(blob[:data]))
        value.is_a?(Hash) ? value : {}
      rescue StandardError => e
        # Runs after the transaction committed the header and blobs, so nothing here
        # may fail the write: a bad `__start__` costs the goal backfill only.
        ::Gitlab::ErrorTracking.track_exception(e, workflow_id: @workflow.id)
        {}
      end

      # Live progress for messaging-triggered workflows. Gated on the adapter
      # opting in, and debounced (see ProgressDeliveryWorker) so quiet or
      # non-streaming workflows schedule nothing.
      def enqueue_messaging_progress_delivery
        return enqueue_child_session_progress if @workflow.messaging_callback_context.blank?
        return unless messaging_adapter_supports_live_progress?

        ::Ai::Messaging::ProgressDeliveryWorker.perform_in(
          ::Ai::Messaging::ProgressDeliveryWorker::DEBOUNCE_INTERVAL, @workflow.id
        )
      end

      # A delegated session has no surface of its own, but its card on the parent's surface follows it.
      # The checkpoint is already saved, so a failed lookup must not fail the request.
      def enqueue_child_session_progress
        return unless @workflow.parent_workflow_id
        return unless ::Ai::Messaging::ChildSession.relayed?(@workflow)

        ::Ai::Messaging::ChildSessionCardWorker.perform_in(
          ::Ai::Messaging::ChildSessionCardWorker::DEBOUNCE_INTERVAL, @workflow.id
        )
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e, workflow_id: @workflow.id)
      end

      def messaging_adapter_supports_live_progress?
        adapter_key = @workflow.messaging_callback_context['adapter']
        adapter_class = ::Ai::Messaging::AdapterRegistry[adapter_key]
        adapter_class&.supports_live_progress?
      end

      def incremental_checkpoints_enabled?
        @workflow.incremental_checkpoints_enabled?
      end

      # Incremental workflows write a header for every checkpoint, so headers are
      # the durable first-run signal even after full rows age out via the TTL or
      # once full writes stop. Non-incremental workflows only have the full table.
      def first_checkpoint?
        if incremental_checkpoints_enabled?
          !@workflow.checkpoint_headers.exists?
        else
          !@workflow.checkpoints.exists?
        end
      end

      # Incremental-only never saves the full row, so a validated checkpoint
      # (no errors) means the header and blobs committed.
      def checkpoint_written?(checkpoint)
        incremental_checkpoints_enabled? ? checkpoint.errors.empty? : checkpoint.persisted?
      end

      # After the commit: a failed publish must not 400 a durable write.
      def publish_checkpoint(checkpoint)
        GraphqlTriggers.workflow_events_updated(published_event(checkpoint))
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e, workflow_id: @workflow.id)
      end

      def published_event(checkpoint)
        return checkpoint if checkpoint.persisted?
        return @workflow unless @workflow.incremental_blob_gate.reconstruct?

        @workflow.checkpoint_headers.for_checkpoint_ns(checkpoint.checkpoint_ns).in_checkpoint_order.last
      end

      def checkpoint_attributes
        @params.except(:channel_blobs, :channel_keys, :model_metadata_json, :flow_metadata_json)
               .merge(workflow: @workflow)
      end

      def channel_blobs_params
        @params[:channel_blobs]
      end

      def write_checkpoint_header(checkpoint)
        # Detached instance (not `@workflow.checkpoint_headers.new`): bulk_insert!
        # doesn't mark it persisted, so keeping it off the association avoids a
        # later `@workflow.update!` autosaving and re-inserting it. Mirrors blobs.
        now = Time.current
        header = ::Ai::DuoWorkflows::CheckpointHeader.new(
          workflow: @workflow,
          # Partition key: pins the header to the workflow's daily partition.
          workflow_created_at: @workflow.created_at,
          thread_ts: checkpoint.thread_ts,
          parent_ts: checkpoint.parent_ts,
          # Which langgraph lineage this row belongs to (see Checkpoint#checkpoint_ns).
          checkpoint_ns: checkpoint.checkpoint_ns,
          current_thread: checkpoint.current_thread,
          # Slim header: channel_values is reconstructed from blobs on read.
          checkpoint: checkpoint.checkpoint.except('channel_values', :channel_values),
          # Blobs cannot express a deletion, so the read path needs the live
          # membership to select from the union of every channel ever blobbed.
          channel_keys: channel_keys(checkpoint),
          metadata: checkpoint.metadata,
          created_at: now,
          updated_at: now
        )

        # Append-only (no unique index): a re-sent checkpoint writes another header
        # row, matching p_duo_workflows_checkpoints; readers take the latest.
        @workflow.checkpoint_headers.bulk_insert!([header])
      end

      # An Array (even empty) is authoritative and wins over channel_values, which
      # incremental-only mode drops. nil means no param, so derive from the payload.
      def channel_keys(checkpoint)
        from_params = @params[:channel_keys]
        return from_params.map(&:to_s) if from_params.is_a?(Array)

        derived_channel_keys(checkpoint)
      end

      # The endpoint caps the param; the derived list is uncapped and would hit the
      # column's check constraint. Raise for a legible 400 (execute rescues it).
      def derived_channel_keys(checkpoint)
        keys = channel_values(checkpoint)&.keys&.map(&:to_s)
        limit = ::Ai::DuoWorkflows::CheckpointHeader::CHANNEL_KEYS_LIMIT
        return keys if keys.nil? || keys.size <= limit

        raise ArgumentError, "channel_values has #{keys.size} channels, " \
          "more than the #{limit} a checkpoint header can record"
      end

      # A non-Hash value is a malformed payload. Return nil so callers skip it
      # instead of raising a 500 the API does not rescue.
      def channel_values(checkpoint)
        values = checkpoint.checkpoint['channel_values'] || checkpoint.checkpoint[:channel_values]
        values if values.is_a?(Hash)
      end

      def build_blobs_batch(checkpoint)
        # Partition key: pins every blob to the workflow's daily partition. See
        # CheckpointBlob#partitioned_by.
        workflow_created_at = @workflow.created_at
        # bulk_insert! (insert_all) does not set timestamps, so set them here.
        now = Time.current
        channel_blobs_params.map do |attrs|
          # Detached instances (not `@workflow.checkpoint_blobs.new`): bulk_insert!
          # doesn't mark them persisted, so keeping them off the association avoids
          # a later `@workflow.update!` autosaving and re-inserting every blob.
          ::Ai::DuoWorkflows::CheckpointBlob.new(
            attrs.merge(
              workflow: @workflow,
              workflow_created_at: workflow_created_at,
              # Decode to raw bytes for the bytea column, dropping base64 overhead.
              data: Base64.strict_decode64(attrs[:data]),
              thread_ts: checkpoint.thread_ts,
              current_thread: checkpoint.current_thread,
              created_at: now,
              updated_at: now
            )
          )
        end
      end
    end
  end
end
