# frozen_string_literal: true

module Geo
  module VerificationStateDefinition
    extend ActiveSupport::Concern
    include Delay
    include EachBatch
    include Gitlab::Geo::LogHelpers

    included do
      validates :verification_failure, length: { maximum: 255 }

      # Defaults to the primary key. Pass a column when that is not the one you are paging by:
      # some state tables have their own surrogate `id` primary key, so the column holding the
      # model id is a different one (see Geo::VerificationState#verification_state_model_key).
      #
      # Kept as a bound `?` rather than Arel because Geo::BaseBatchBulkUpdateService loads its
      # cursor from JSON and can hand this an array, which `?` flattens and Arel does not. The
      # column is always a code-defined identifier, never caller input.
      scope :after_cursor, ->(cursor, column = nil) {
        where("#{column || primary_key} > ?", cursor) if cursor
      }
      scope :keyset_order, ->(attributes) { order(Gitlab::Pagination::Keyset::Order.build(attributes)) }
      scope :verification_state_not_pending, -> {
        where.not(verification_state: VerificationState::VERIFICATION_STATE_VALUES[:verification_pending])
      }
      scope :verified_after, ->(timestamp) { where(arel_table[:verified_at].gteq(timestamp)) }

      # Used by the Geo cleanup tools (Geo::Tools) to find records whose verification failed
      # with a known error text. The indexed verification_state filter is chained first
      # because the free-text match is not index-backed, so this is for on-demand
      # diagnostics, not a frequent cron.
      scope :with_verification_failure_matching, ->(pattern) {
        where(verification_state: VerificationState::VERIFICATION_STATE_VALUES[:verification_failed])
          .where(arel_table[:verification_failure].matches("%#{sanitize_sql_like(pattern)}%"))
      }

      # Records that have failed verification at least `count` times. Used by the Geo cleanup
      # tools to require a persistent failure before acting on a record, so a transient storage
      # problem is less likely to look like a permanently missing file. Needs no index of its
      # own: it only narrows the already-filtered failed set. NULL counts are excluded, which
      # is the conservative direction.
      scope :with_verification_retry_count_at_least, ->(count) { where(verification_retry_count: count..) }

      state_machine :verification_state, initial: :verification_pending do
        state :verification_pending, value: VerificationState::VERIFICATION_STATE_VALUES[:verification_pending]
        state :verification_started, value: VerificationState::VERIFICATION_STATE_VALUES[:verification_started]
        state :verification_succeeded, value: VerificationState::VERIFICATION_STATE_VALUES[:verification_succeeded] do
          validates :verification_checksum, presence: true
        end
        state :verification_failed, value: VerificationState::VERIFICATION_STATE_VALUES[:verification_failed] do
          validates :verification_failure, presence: true
        end
        state :verification_disabled, value: VerificationState::VERIFICATION_STATE_VALUES[:verification_disabled]

        before_transition any => :verification_started do |instance, _|
          instance.verification_started_at = Time.current
        end

        before_transition [:verification_pending, :verification_started,
          :verification_succeeded] => :verification_pending do |instance, transition|
          # Skip cleanup on a loopback so a clean pending-to-pending transition stays a no-op.
          # Every other transition changes verification_state, so an UPDATE happens anyway.
          instance.clear_verification_failure_fields! unless transition.loopback?
        end

        before_transition [:verification_failed, :verification_disabled] => :verification_pending do |instance, _|
          # If transitioning from verification_failed, then don't clear
          # verification_retry_count and verification_retry_at to ensure
          # progressive backoff of syncs-due-to-verification-failures.
          #
          # verification_disabled is included because a resync triggered by a
          # verification failure passes through it: `before_verification_failed`
          # calls `failed`, and the resync's `:start` transition disables
          # verification (see Geo::VerifiableRegistry#before_started). Clearing
          # here would reset verification_retry_count on every resync, so it
          # could never exceed 1 and the backoff above would never progress.
          instance.clear_verification_failure!
        end

        before_transition any => :verification_failed do |instance, _|
          instance.before_verification_failed
        end

        before_transition any => :verification_succeeded do |instance, _|
          instance.verified_at = Time.current
          instance.clear_verification_failure_fields!
        end

        after_transition any => [:verification_pending, :verification_started,
          :verification_succeeded] do |object, transition|
          object.log_verification_transition(:debug, object, transition)
        end

        after_transition any => :verification_disabled do |object, transition|
          object.log_verification_transition(:info, object, transition)
        end

        after_transition any => :verification_failed do |object, transition|
          object.log_verification_transition(:warn, object, transition)
        end

        event :verification_started do
          transition any => :verification_started
        end

        event :verification_succeeded do
          transition verification_started: :verification_succeeded
        end

        event :verification_failed do
          transition any => :verification_failed
        end

        event :verification_disabled do
          transition any => :verification_disabled
        end

        event :verification_pending do
          transition any => :verification_pending
        end
      end
    end

    # Overridden by Geo::VerifiableRegistry
    def clear_verification_failure_fields!
      # Persist retry resets even when a stale copy already holds zero/nil.
      verification_retry_count_will_change!
      verification_retry_at_will_change!
      self.verification_retry_count = 0
      self.verification_retry_at = nil
      clear_verification_failure!
    end

    # Force column into UPDATE even when in-memory value is nil; a stale copy must clear
    # a concurrently-written DB failure. Plain `= nil` is a dirty-tracking no-op.
    # https://gitlab.com/gitlab-org/gitlab/-/work_items/627715
    def clear_verification_failure!
      verification_failure_will_change!
      self.verification_failure = nil
    end

    # Overridden by Geo::VerifiableRegistry
    def before_verification_failed
      # Force the column into the UPDATE even when the message is unchanged. Another
      # process may have NULLed it (verification_pending!) since this row was loaded,
      # which would otherwise leave verification_failed with no message.
      # https://gitlab.com/gitlab-org/gitlab/-/work_items/601974
      verification_failure_will_change!

      self.verification_retry_count ||= 0
      self.verification_retry_count += 1
      self.verification_retry_at = next_retry_time(self.verification_retry_count)
      self.verified_at = Time.current
    end

    def log_verification_transition(level, object, transition)
      case level
      when :debug
        object.log_debug("Verification state transition", verification_transition_details(object, transition))
      when :info
        object.log_info("Verification state transition", verification_transition_details(object, transition))
      when :warn
        object.log_warning("Verification state transition", verification_transition_details(object, transition))
      end
    end

    def verification_transition_details(object, transition)
      model_record_id =
        if object.respond_to?(:model_record_id)
          object.model_record_id
        elsif self.class.respond_to?(:separate_verification_state_table?)
          # This is a Model class like `Project`, as opposed to `Geo::ProjectState`.
          object.id
        else # rubocop:disable Style/EmptyElse -- for clarity!
          nil
        end

      {
        id: object.id,
        model_record_id: model_record_id,
        from: transition.from_name.to_s,
        to: transition.to_name.to_s,
        result: transition.result
      }
    end

    def verification_state_name_no_prefix
      verification_state_name.to_s.gsub('verification_', '')
    end

    # Returns true if all verification fields are in their default state.
    # Used during migration from replicable table to state table to determine
    # if we should copy the checksum from the replicable table.
    # https://gitlab.com/gitlab-org/gitlab/-/merge_requests/208182
    # TODO: Remove after verification data migration is complete (https://gitlab.com/gitlab-org/gitlab/-/issues/515874)
    def verification_fields_default?
      verification_pending? &&
        verified_at.nil? &&
        verification_started_at.nil? &&
        verification_retry_at.nil? &&
        verification_checksum.nil? &&
        verification_failure.blank? &&
        verification_retry_count.to_i == 0
    end
  end
end
