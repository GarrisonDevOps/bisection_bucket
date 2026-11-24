# frozen_string_literal: true

module Namespaces
  # Applies the pending state propagations for a namespace subtree.
  #
  # Takes the namespace's outbox records oldest first, one at a time. For each, it
  # computes the overwritable states, marks the record `processing`, walks the
  # descendant subtree in batches applying a conditional bulk update, and deletes
  # the record on completion. A record runs only after every older one finished,
  # so its `source_state` matches what descendants inherit.
  #
  # See https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/group_and_project_operations_and_state_management/decisions/003_state_propagation_model/
  class StatePropagationService
    include Gitlab::Loggable

    STATE_PROPAGATION_ITERATOR_BATCH_SIZE = 200

    # Checked only between records, so a job may overrun by one record's walk.
    MAX_RUNTIME = 3.minutes

    # Key under which a descendant's pre-deletion state is preserved, shared with StatePreservation.
    DELETION_PRESERVATION_KEY = 'schedule_deletion'

    def initialize(namespace_id)
      @namespace_id = namespace_id
    end

    def execute
      runtime_limiter = Gitlab::Metrics::RuntimeLimiter.new(MAX_RUNTIME)

      loop do
        propagation = counting_failures('unknown') { Namespaces::StatePropagation.next_for(namespace_id) }
        # An older record that is still processing blocks the rest until it finishes or
        # StatePropagationCronWorker resets it.
        break if propagation.nil? || propagation.status_processing?

        if runtime_limiter.was_over_time?
          # Dropped as a duplicate while this job holds the until_executed key; `reschedule_once`
          # on the worker runs it again once this job finishes.
          Namespaces::StatePropagationWorker.perform_async(namespace_id)
          break
        end

        break unless counting_failures(propagation.target_state) { apply(propagation) }

        # Records the check; the next pass re-enqueues only if a record remains.
        runtime_limiter.over_time?
      end
    end

    private

    attr_reader :namespace_id

    # Increments the failure metric for +target_state+ when the block raises, then re-raises.
    #
    # @param target_state [String] the metric label
    # @return [Object] the block's return value
    def counting_failures(target_state)
      yield
    rescue StandardError
      Gitlab::NamespaceStatePropagation::Metrics.increment_failures(target_state)
      raise
    end

    # Propagates one outbox record to the descendants and deletes it.
    #
    # @param propagation [Namespaces::StatePropagation]
    # @return [Boolean] false when another job claimed the record first
    def apply(propagation)
      overwritable_states = Namespaces::Stateful::StatePrecedence.overwritable_states(
        propagation.source_state.to_sym,
        propagation.target_state.to_sym
      )

      # Nothing to propagate: drop the outbox record without a wasted status write.
      if overwritable_states.empty?
        propagation.destroy!
        return true
      end

      return false unless propagation.claim

      log_started(propagation)

      # These steps are intentionally not wrapped in a single transaction: propagation
      # can update very large descendant subtrees in batches, and one transaction would
      # hold locks for too long. A raised error returns the record to `pending` for the
      # Sidekiq retry; if the process dies, StatePropagationCronWorker reclaims it.
      start_time = Gitlab::Metrics::System.monotonic_time

      result = begin
        propagate(propagation, overwritable_states)
      rescue StandardError => e
        log_failed(propagation, e)
        propagation.release
        raise
      end

      duration = Gitlab::Metrics::System.monotonic_time - start_time

      propagation.destroy!

      Gitlab::NamespaceStatePropagation::Metrics.observe_duration(propagation.target_state, duration)

      log_completed(propagation, result, duration)

      true
    end

    def propagate(propagation, overwritable_states)
      source_state = propagation.source_state
      target_state = propagation.target_state
      cursor = { current_id: namespace_id, depth: [namespace_id] }

      # The traversal must keep descending through descendants already in target_state
      # as well as those still in an overwritable state, so the filter includes
      # target_state. The conditional UPDATE below guarantees only overwritable
      # descendants actually change state.
      # Normalise to symbols so the filter never mixes symbol and string states.
      state_filter = (overwritable_states + [target_state.to_sym]).uniq

      iterator = Gitlab::Database::Namespaces::StatePropagationIterator.new(
        cursor: cursor,
        state_filter: state_filter,
        on_rewind: -> { Gitlab::NamespaceStatePropagation::Metrics.increment_boundary_rewinds },
        options: { preserve_descendants_deletion: cancel_deletion?(source_state, target_state) }
      )

      overwrite_options = preservation_options(source_state, target_state)
      overwrite_options = overwrite_options.merge(
        # Only restore namespaces that are still in the source state. Ensures idempotency when a
        # propagation is re-run after it fails midway.
        from: overwrite_options[:mode] == :restore ? [source_state.to_sym] : overwritable_states,
        to: target_state
      )

      batch_count = 0
      descendants_updated = 0

      iterator.each_batch(of: STATE_PROPAGATION_ITERATOR_BATCH_SIZE) do |ids|
        batch_count += 1
        # The origin already transitioned, and may have transitioned again since this record was written.
        descendant_ids = ids - [namespace_id]
        descendants_updated += Namespace.overwrite_state_in_batch(descendant_ids, **overwrite_options)

        # Heartbeat: keeps a long-running propagation from being treated as stuck by
        # StatePropagationCronWorker and re-run concurrently.
        propagation.touch(:started_at)

        Gitlab::NamespaceStatePropagation::Metrics.increment_batches(target_state)
      end

      { batch_count: batch_count, descendants_updated: descendants_updated }
    end

    def log_started(propagation)
      Gitlab::AppLogger.info(build_structured_payload_labkit(
        Labkit::Fields::LOG_MESSAGE => 'Namespace state propagation started',
        Labkit::Fields::GL_NAMESPACE_ID => namespace_id,
        source_state: propagation.source_state.to_s,
        target_state: propagation.target_state.to_s
      ))
    end

    def log_completed(propagation, result, duration)
      Gitlab::AppLogger.info(build_structured_payload_labkit(
        Labkit::Fields::LOG_MESSAGE => 'Namespace state propagation completed',
        Labkit::Fields::GL_NAMESPACE_ID => namespace_id,
        target_state: propagation.target_state.to_s,
        batch_count: result[:batch_count],
        Labkit::Fields::DURATION_S => duration.round(6),
        descendants_updated: result[:descendants_updated]
      ))
    end

    def log_failed(propagation, error)
      Gitlab::AppLogger.error(build_structured_payload_labkit(
        Labkit::Fields::LOG_MESSAGE => 'Namespace state propagation failed',
        Labkit::Fields::GL_NAMESPACE_ID => namespace_id,
        target_state: propagation.target_state.to_s,
        Labkit::Fields::ERROR_TYPE => error.class.name,
        Labkit::Fields::ERROR_MESSAGE => error.message
      ))
    end

    def preservation_options(source_state, target_state)
      # Exiting maintenance into deletion_scheduled is a reversal: descendants keep what they preserved.
      if target_state == 'deletion_scheduled' && source_state != 'maintenance'
        { mode: :preserve, preservation_key: DELETION_PRESERVATION_KEY }
      # Cancelling deletion restores each descendant to the state it preserved, then removes it.
      elsif cancel_deletion?(source_state, target_state)
        { mode: :restore, preservation_key: DELETION_PRESERVATION_KEY }
      elsif source_state == 'archived' && target_state == 'ancestor_inherited'
        { mode: :clear }
      else
        {}
      end
    end

    def cancel_deletion?(source_state, target_state)
      return false unless source_state == 'deletion_scheduled'

      Namespaces::Stateful::StatePrecedence.reversal?(source_state.to_sym, target_state.to_sym)
    end
  end
end
