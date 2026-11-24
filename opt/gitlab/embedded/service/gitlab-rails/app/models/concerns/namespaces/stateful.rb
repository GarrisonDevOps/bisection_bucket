# frozen_string_literal: true

module Namespaces
  module Stateful
    extend ActiveSupport::Concern

    # States whose value is inherited by descendants and resolved through ancestor traversal.
    # See ADR 003 - State propagation model:
    # https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/group_and_project_operations_and_state_management/decisions/003_state_propagation_model/
    PROPAGATED_STATES = %i[ancestor_inherited archived deletion_scheduled maintenance].freeze

    # Transient, in-progress states that apply only to the namespace itself and are never propagated.
    NON_PROPAGATED_STATES = %i[creation_in_progress deletion_in_progress transfer_in_progress transfer_scheduled].freeze

    # Preserve event whose saved state is the last propagated state before entering this
    # non-propagated state. Entering a non-propagated state never changes descendants.
    NON_PROPAGATED_STATE_PRESERVE_EVENTS = {
      deletion_in_progress: :start_deletion,
      transfer_scheduled: :schedule_transfer,
      transfer_in_progress: :schedule_transfer
    }.freeze

    included do
      include ::Gitlab::TenantContainerLifecycle::Stateful::TransitionContext
      include TransitionCallbacks
      include StatePreservation
      include TransitionValidation
      include ::Gitlab::TenantContainerLifecycle::Stateful::TransitionLogging
      include StateQuerying

      attribute :state, :integer, limit: 2, default: 0

      enum :state, {
        ancestor_inherited: 0,
        archived: 1,
        deletion_scheduled: 2,
        creation_in_progress: 3,
        deletion_in_progress: 4,
        transfer_in_progress: 5,
        maintenance: 6,
        transfer_scheduled: 7
      }, instance_methods: false

      scope :with_state, ->(states) { where(state: states) }

      state_machine :state, initial: :ancestor_inherited do
        state :creation_in_progress
        state :maintenance

        before_transition :validate_ancestors_state
        # Must run before handle_state_preservation, which clears preserved states on restore events.
        before_transition :capture_last_propagated_state
        before_transition :handle_state_preservation
        before_transition :update_state_metadata
        before_transition on: :schedule_deletion, do: :ensure_transition_user
        before_transition on: :schedule_deletion, do: :set_deletion_schedule_data
        before_transition on: :cancel_deletion, do: :clear_deletion_schedule_data
        before_transition on: :cancel_deletion, do: :clear_deletion_data
        before_transition on: :schedule_transfer, do: :ensure_transition_user
        before_transition on: :schedule_transfer, do: :set_transfer_schedule_data
        before_transition on: :start_transfer, do: :ensure_transition_user
        before_transition on: :start_transfer, do: :set_transfer_data
        before_transition on: :complete_transfer, do: :clear_transfer_data
        before_transition on: :cancel_transfer, from: :transfer_scheduled, do: :clear_transfer_data
        before_transition on: :cancel_transfer, from: :transfer_in_progress, do: :clear_transfer_data_preserving_target
        before_transition on: :schedule_deletion, do: :set_deletion_data
        # Declared after the clear_transfer_data* callbacks: state_machine runs before_transition
        # hooks in declaration order, and those two clear `transfer_last_error`.
        before_transition on: :cancel_transfer, do: :set_transfer_error_data
        before_transition on: :reschedule_deletion, do: :set_deletion_error_data

        event :archive do
          transition ancestor_inherited: :archived
        end

        event :unarchive do
          transition archived: :ancestor_inherited
          transition ancestor_inherited: :ancestor_inherited,
            unless: :remove_ancestor_inherited_transitions?
        end

        event :schedule_deletion do
          transition %i[ancestor_inherited archived] => :deletion_scheduled
        end

        event :start_deletion do
          # Descendant states are not propagated yet, so a descendant stuck in a
          # transient state must not block deletion of its ancestors.
          transition any => :deletion_in_progress
        end

        event :reschedule_deletion do
          transition deletion_in_progress: :ancestor_inherited,
            if: :restore_to_ancestor_inherited_on_reschedule_deletion?
          transition deletion_in_progress: :archived, if: :restore_to_archived_on_reschedule_deletion?
          transition deletion_in_progress: :deletion_scheduled,
            if: :restore_to_deletion_scheduled_on_reschedule_deletion?
          transition deletion_in_progress: :deletion_scheduled
          transition ancestor_inherited: :deletion_scheduled
        end

        event :cancel_deletion do
          transition %i[deletion_scheduled deletion_in_progress] => :archived,
            if: :restore_to_archived_on_cancel_deletion?
          transition %i[deletion_scheduled deletion_in_progress] => :ancestor_inherited
          transition ancestor_inherited: :archived, if: :restore_to_archived_on_cancel_deletion?
          transition ancestor_inherited: :ancestor_inherited,
            unless: :remove_ancestor_inherited_transitions?
        end

        event :schedule_transfer do
          transition %i[ancestor_inherited archived] => :transfer_scheduled
        end

        event :start_transfer do
          transition transfer_scheduled: :transfer_in_progress
        end

        event :complete_transfer do
          transition transfer_in_progress: :archived,
            if: :restore_to_archived_on_complete_transfer?
          transition transfer_in_progress: :ancestor_inherited
        end

        event :cancel_transfer do
          transition %i[transfer_scheduled transfer_in_progress] => :archived,
            if: :restore_to_archived_on_cancel_transfer?
          transition %i[transfer_scheduled transfer_in_progress] => :ancestor_inherited
        end

        after_transition :log_transition
        after_transition to: :archived, do: :invalidate_namespace_descendants_cache
        after_transition from: :archived, do: :invalidate_namespace_descendants_cache
        after_transition to: PROPAGATED_STATES, do: :create_state_propagation_outbox

        after_failure :update_state_metadata_on_failure
        after_failure :log_transition_failure
      end

      private

      def remove_ancestor_inherited_transitions?
        false
      end

      def stateful_detail
        namespace_details
      end

      def invalidate_namespace_descendants_cache
        return if is_a?(Namespaces::UserNamespace)

        if is_a?(Namespaces::ProjectNamespace)
          Namespaces::Descendants.expire_for([parent_id])
        else
          Namespaces::Descendants.expire_recursive_for(self)
        end
      end

      def capture_last_propagated_state(transition)
        from_state = transition.from_name

        @last_propagated_state =
          if NON_PROPAGATED_STATES.include?(from_state)
            preserve_event = NON_PROPAGATED_STATE_PRESERVE_EVENTS[from_state]
            preserve_event && preserved_state(preserve_event)
          else
            from_state
          end
      end

      def create_state_propagation_outbox(transition)
        return if @last_propagated_state == transition.to_name
        # Without a known inherited state there is nothing on descendants to revert.
        return if @last_propagated_state.nil? && transition.to_name == :ancestor_inherited
        return if is_a?(Namespaces::ProjectNamespace)
        return unless Feature.enabled?(:namespace_state_propagation_outbox, root_ancestor)

        source_state = (@last_propagated_state || transition.from_name).to_s
        target_state = transition.to_name.to_s

        Namespaces::StatePropagation.insert!({
          namespace_id: id,
          source_state: source_state,
          target_state: target_state,
          status: :pending
        })

        run_after_commit { Namespaces::StatePropagationWorker.perform_async(id) }
      end

      def stateful_log_metadata
        { message: 'Namespace state transition', namespace_id: id }
      end
    end

    class_methods do
      # Bulk state update for propagation: only rows in a `from` state move to `to`.
      # Preserved states follow {Namespaces::Stateful::StatePreservation}.
      #
      # @param ids [Array<Integer>] namespace IDs in the batch
      # @param from [Array<Symbol>] states that may be overwritten
      # @param to [Symbol] state to move rows to; with :restore, the minimum state
      # @param mode [Symbol] what happens to preserved states:
      #   :overwrite leaves them untouched,
      #   :preserve saves each row's previous state under `preservation_key`,
      #   :restore moves each row to the state saved under `preservation_key` (or `to` if higher) and removes it,
      #   :clear removes all of them
      # @param preservation_key [String, nil] preserved_states key used by :preserve and :restore
      # @raise [ArgumentError] if `mode` is not recognized
      # @return [Integer] number of rows whose state changed
      def overwrite_state_in_batch(ids, from:, to:, mode: :overwrite, preservation_key: nil)
        transaction do
          rows = lock_states(ids, from)
          next 0 if rows.empty?

          locked_ids = rows.map(&:first)

          case mode
          when :restore
            restored_count = restore_states(rows, to, preservation_key)
            clear_preserved_states(locked_ids)
            restored_count
          when :preserve
            preserve_states(rows, preservation_key)
            id_in(locked_ids).update_all(state: states[to])
          when :clear
            clear_preserved_states(locked_ids)
            id_in(locked_ids).update_all(state: states[to])
          when :overwrite
            id_in(locked_ids).update_all(state: states[to])
          else
            raise ArgumentError, "Unknown overwrite mode: #{mode.inspect}"
          end
        end
      end

      private

      # Lock namespaces before namespace_details, the same order as a regular transition, to avoid deadlocks.
      def lock_states(ids, from)
        with_state(from).id_in(ids).order(:id).lock('FOR NO KEY UPDATE').limit(ids.size).pluck(:id, :state)
      end

      def preserve_states(rows, preservation_key)
        Namespace::Detail.insert_all(rows.map { |id, _| { namespace_id: id } }, unique_by: :namespace_id)

        rows.group_by(&:last).each do |state, state_rows|
          Namespace::Detail
            .where(namespace_id: state_rows.map(&:first))
            .update_all(
              [
                "state_metadata = jsonb_set(state_metadata, '{preserved_states}', " \
                  "COALESCE(state_metadata -> 'preserved_states', '{}'::jsonb) || " \
                  "jsonb_build_object(?, ?::text), true)",
                preservation_key,
                state
              ]
            )
        end
      end

      # Moves each row to its preserved state, with one UPDATE per distinct state.
      #
      # @param rows [Array<Array(Integer, String)>] locked namespace ID and current state pairs
      # @param minimum_state [Symbol] the least restrictive state a row may be restored to
      # @param preservation_key [String] preserved_states key holding each row's state to restore
      # @return [Integer] number of rows whose state changed
      def restore_states(rows, minimum_state, preservation_key)
        ids = rows.map(&:first)
        preserved_state = Arel.sql("state_metadata -> 'preserved_states' ->> #{connection.quote(preservation_key)}")
        preserved_states = Namespace::Detail
          .where(namespace_id: ids)
          .limit(ids.size)
          .pluck(:namespace_id, preserved_state)
          .to_h

        # A descendant is never restored to a state less restrictive than its parent's.
        rows_by_restored_state = rows.group_by do |id, _state|
          StatePrecedence.highest(preserved_states[id], minimum_state)
        end

        rows_by_restored_state.sum do |restored_state, state_rows|
          changed_ids = state_rows.filter_map { |id, state| id unless state.to_sym == restored_state }
          next 0 if changed_ids.empty?

          id_in(changed_ids).update_all(state: states[restored_state])
        end
      end

      def clear_preserved_states(ids)
        Namespace::Detail
          .where(namespace_id: ids)
          .where("(state_metadata -> 'preserved_states') IS NOT NULL")
          .update_all("state_metadata = state_metadata - 'preserved_states'")
      end
    end
  end
end
