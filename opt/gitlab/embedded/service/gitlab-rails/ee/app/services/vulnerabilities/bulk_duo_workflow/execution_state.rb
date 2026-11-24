# frozen_string_literal: true

module Vulnerabilities
  module BulkDuoWorkflow
    class ExecutionState
      include ::Vulnerabilities::BulkDuoWorkflow::StateKeys

      TTL = 7.days
      BATCH_SIZE = 100
      CANCEL_PENDING_BATCH_SIZE = 1_000

      STATUS_CREATED = :created
      STATUS_RUNNING = :running
      STATUS_ALREADY_RUNNING = :already_running
      STATUS_COMPLETED = :completed
      STATUS_FAILED = :failed
      STATUS_CANCELLED = :cancelled

      RESULT_NOT_FOUND = :not_found
      RESULT_INVALID = :invalid

      PROJECT_ID_REQUIRED = 'project_id is required'
      WORKFLOW_REQUIRED = 'workflow is required'

      TERMINAL_STATES = [
        STATUS_COMPLETED,
        STATUS_FAILED,
        STATUS_CANCELLED
      ].freeze

      ITEM_STATES = %i[
        pending
        processing
        completed
        failed
        cancelled
      ].freeze

      attr_reader :execution_id, :workflow

      def self.current(project_id:, workflow:)
        execution_id = redis.with do |r|
          r.get(
            StateKeys.current_execution_key(
              project_id: project_id,
              workflow: workflow
            )
          )
        end

        return unless execution_id

        execution = new(
          execution_id: execution_id,
          project_id: project_id,
          workflow: workflow
        )

        return execution if execution.active?

        nil
      end

      def self.latest(project_id:, workflow:)
        execution_id = redis.with do |r|
          r.get(
            StateKeys.latest_execution_key(
              project_id: project_id,
              workflow: workflow
            )
          )
        end

        return unless execution_id

        fetch(
          execution_id: execution_id,
          project_id: project_id,
          workflow: workflow
        )
      end

      def self.create!(project_id:, workflow:, stages:, batch_size: BATCH_SIZE, metadata: {})
        execution_id = SecureRandom.uuid

        execution = new(
          execution_id: execution_id,
          project_id: project_id,
          workflow: workflow
        )

        actual_execution_id = execution.create!(
          stages: stages,
          batch_size: batch_size,
          metadata: metadata
        )

        return execution if actual_execution_id == execution.execution_id

        new(
          execution_id: actual_execution_id,
          project_id: project_id,
          workflow: workflow
        )
      end

      def self.fetch(execution_id:, project_id:, workflow:)
        execution = new(
          execution_id: execution_id,
          project_id: project_id,
          workflow: workflow
        )

        execution if execution.exists?
      end

      def self.redis
        Gitlab::Redis::SharedState
      end

      def initialize(execution_id:, project_id:, workflow:)
        raise ArgumentError, PROJECT_ID_REQUIRED if project_id.nil?
        raise ArgumentError, WORKFLOW_REQUIRED if workflow.nil?

        @execution_id = execution_id
        @project_id = project_id
        @workflow = workflow
      end

      def create!(stages:, batch_size:, metadata: {})
        scripts.create(
          execution_id: execution_id,
          project_id: project_id,
          workflow: workflow,
          stages: stages,
          batch_size: batch_size,
          metadata: metadata
        )
      end

      def append_to_stage!(stage:, item_ids:)
        state.append_stage!(
          index: stage_order(stage),
          item_ids: item_ids
        )
      end

      def start!
        scripts.start(execution_id: execution_id)
      end

      def cancel!
        transition!(STATUS_CANCELLED)
      end

      def complete!
        transition!(STATUS_COMPLETED)
      end

      def fail!
        transition!(STATUS_FAILED)
      end

      def start_processing!(item_ids)
        state.start_processing!(item_ids)
      end

      def mark_completed!(item_ids)
        handle_finish_result(state.mark_completed!(item_ids))
      end

      def mark_failed!(item_ids)
        handle_finish_result(state.mark_failed!(item_ids))
      end

      def mark_cancelled!(item_ids, stage_order: nil)
        handle_finish_result(state.mark_cancelled!(item_ids, stage_order: stage_order))
      end

      def cancel_pending!
        stages.each do |stage|
          loop do
            moved = state.cancel_pending!(stage_order: stage['order'], limit: CANCEL_PENDING_BATCH_SIZE)

            break if moved < CANCEL_PENDING_BATCH_SIZE
          end
        end
      end

      def active?
        status.present? && TERMINAL_STATES.exclude?(status)
      end

      def exists?
        metadata[:execution_id].present?
      end

      def status
        metadata[:status]
      end

      def batch_size
        metadata[:batch_size]
      end

      def workflow_metadata
        metadata[:metadata]
      end

      def initiator_id
        workflow_metadata['initiator_id']
      end

      def next_batch
        limit = batch_size
        limit = BATCH_SIZE if limit <= 0

        state.pending_ids(limit: limit)
      end

      def pending_ids(limit: nil)
        metadata[:stages].each_with_object([]) do |stage, ids|
          break ids if limit && ids.size >= limit

          ids.concat(
            state.pending_ids(
              stage_order: stage['order'],
              limit: limit && (limit - ids.size)
            )
          )
        end
      end

      def pending_ids_by_stage
        metadata[:stages].to_h do |stage|
          [
            stage['order'],
            state.pending_ids(stage_order: stage['order'])
          ]
        end
      end

      def snapshot
        metadata.merge(
          pending_ids: pending_ids,
          processing_ids: state.processing_ids,
          completed_ids: state.completed_ids,
          failed_ids: state.failed_ids,
          cancelled_ids: state.cancelled_ids
        )
      end

      def created_at
        metadata[:created_at]
      end

      def started_at
        metadata[:started_at]
      end

      def ended_at
        metadata[:ended_at]
      end

      def cancel_requested
        metadata[:cancel_requested]
      end
      alias_method :cancel_requested?, :cancel_requested

      def current_stage
        state = metadata

        state[:stages].find { |stage| stage['order'] == state[:current_stage] }
      end

      def stages
        metadata[:stages]
      end

      def progress
        state = snapshot

        counts = ITEM_STATES.index_with do |item_state|
          state.fetch(:"#{item_state}_ids").size
        end

        total = counts.values.sum
        completed = counts[:completed] + counts[:failed] + counts[:cancelled]

        {
          total: total,
          **counts,
          percentage: total == 0 ? 0.0 : (completed * 100.0 / total)
        }
      end

      def item_states
        state = snapshot

        ITEM_STATES.flat_map do |item_state|
          item_ids = state.fetch(:"#{item_state}_ids")

          item_ids.map do |uuid|
            { uuid: uuid, state: item_state }
          end
        end
      end

      def contains_item?(item_id)
        state.contains_item?(item_id)
      end

      def claim_finish_event?
        self.class.redis.with do |redis|
          !!redis.set(key(:finish_event), '1', nx: true, ex: TTL)
        end
      end

      private

      attr_reader :project_id

      def transition!(status)
        scripts.transition(
          execution_id: execution_id,
          status: status
        )
      end

      def handle_finish_result(result)
        next_item_ids =
          case result
          when VulnerabilityScripts::RESULTS[:stage_complete]
            start_next_batch if state.claim_stage_enqueue!
          when VulnerabilityScripts::RESULTS[:batch_complete]
            start_next_batch if state.claim_batch_enqueue!
          else
            []
          end

        [result, next_item_ids]
      end

      def start_next_batch
        item_ids = next_batch
        return [] if item_ids.empty?

        state.start_processing!(item_ids)

        item_ids
      end

      def state
        @state ||= VulnerabilityState.new(execution_id: execution_id, project_id: project_id, workflow: workflow)
      end

      def scripts
        @scripts ||= ExecutionScripts.new(
          redis: self.class.redis,
          keys: keys,
          ttl: TTL
        )
      end

      def metadata
        raw = self.class.redis.with { |r| r.hgetall(keys[:metadata]) }

        {
          execution_id: raw['execution_id'],
          project_id: raw['project_id'],
          workflow: raw['workflow']&.to_sym,
          status: raw['status']&.to_sym,
          created_at: raw['created_at']&.then { |t| Time.zone.at(t.to_f) },
          started_at: raw['started_at']&.then { |t| Time.zone.at(t.to_f) },
          ended_at: raw['ended_at'].presence&.then { |t| Time.zone.at(t.to_f) },
          cancel_requested: raw['cancel_requested'] == 'true',
          batch_size: raw['batch_size'].to_i,
          processed_in_batch: raw['processed_in_batch'].to_i,
          current_stage: raw['current_stage'].to_i,
          stages: ::Gitlab::Json.safe_parse(raw['stages'] || '[]'),
          metadata: ::Gitlab::Json.safe_parse(raw['metadata'] || '{}')
        }
      end

      def stage_order(stage_name)
        stage = metadata[:stages].find { |definition| definition['name'] == stage_name.to_s }

        raise ArgumentError, "unknown stage: #{stage_name}" unless stage

        stage.fetch('order')
      end

      def current_key
        StateKeys.current_execution_key(
          project_id: project_id,
          workflow: workflow
        )
      end

      def latest_key
        StateKeys.latest_execution_key(
          project_id: project_id,
          workflow: workflow
        )
      end

      def keys
        @keys ||= {
          metadata: key(:metadata),
          current: current_key,
          latest: latest_key
        }
      end
    end
  end
end
