# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class CreateCheckpointWriteBatchService
      include ::Services::ReturnServiceResponses
      include ::Gitlab::Loggable

      # The gateway sends 1-2 writes per batch and the largest observed `data` is
      # 260 characters. See https://gitlab.com/gitlab-org/gitlab/-/work_items/635569
      MAX_WRITES_PER_BATCH = 10
      MAX_DATA_BYTESIZE = 1.kilobyte

      def initialize(workflow:, params:)
        @workflow = workflow
        @params = params
      end

      def execute
        limit = exceeded_limit
        if limit
          log_limit_exceeded(limit)
          return error(limit_error_message(limit), :bad_request)
        end

        @workflow.checkpoint_writes.bulk_insert!(writes_batch)
        success({})
      rescue ActiveRecord::RecordInvalid => err
        error(err.message, :bad_request)
      end

      private

      def exceeded_limit
        if @workflow.status_terminal?
          :terminal_session
        elsif checkpoint_writes.size > MAX_WRITES_PER_BATCH
          :too_many_writes
        elsif checkpoint_writes.any? { |attrs| attrs[:data].to_s.bytesize > MAX_DATA_BYTESIZE }
          :data_too_large
        end
      end

      def limit_error_message(limit)
        case limit
        when :terminal_session
          "Cannot write checkpoints to a #{@workflow.status_name} session"
        when :too_many_writes
          "Too many checkpoint writes: #{checkpoint_writes.size} exceeds the limit of #{MAX_WRITES_PER_BATCH}"
        else # :data_too_large
          "Checkpoint write data exceeds the limit of #{MAX_DATA_BYTESIZE} bytes"
        end
      end

      def log_limit_exceeded(limit)
        ::Gitlab::AppLogger.warn(
          build_structured_payload_labkit(
            message: 'Duo Workflow checkpoint write batch exceeds limits',
            limit_type: limit.to_s,
            Labkit::Fields::DUO_WORKFLOW_ID => @workflow.id,
            Labkit::Fields::GL_USER_ID => @workflow.user_id,
            workflow_status: @workflow.status_name.to_s,
            checkpoint_writes_count: checkpoint_writes.size,
            largest_data_bytesize: checkpoint_writes.map { |attrs| attrs[:data].to_s.bytesize }.max.to_i
          )
        )
      end

      def checkpoint_writes
        @params[:checkpoint_writes]
      end

      def writes_batch
        checkpoint_writes.map do |attrs|
          @workflow.checkpoint_writes.new(
            attrs.merge(thread_ts: @params[:thread_ts])
          )
        end
      end
    end
  end
end
