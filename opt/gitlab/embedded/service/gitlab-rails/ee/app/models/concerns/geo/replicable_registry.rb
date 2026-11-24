# frozen_string_literal: true

module Geo
  module ReplicableRegistry
    extend ActiveSupport::Concern
    include Gitlab::Geo::LogHelpers

    BATCH_SIZE = 1000

    STATE_VALUES = {
      pending: 0,
      started: 1,
      synced: 2,
      failed: 3
    }.freeze

    class_methods do
      include Delay

      def state_value(state_string)
        STATE_VALUES[state_string]
      end

      # Raw `state` column values matched by `with_state(state)`.
      def raw_state_values(state)
        [STATE_VALUES[state]]
      end

      def model_updated_scope(ids)
        model_class.where(id: ids)
      end

      def oldest_unsynced_time
        oldest = nil
        unsynced.each_batch(of: BATCH_SIZE, column: model_foreign_key) do |batch|
          ids = batch.pluck(model_foreign_key) # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- We are already in each_batch
          batch_oldest = model_updated_scope(ids).minimum(model_updated_last)
          oldest = batch_oldest if oldest.nil? || (batch_oldest && batch_oldest < oldest)
        end

        oldest
      end

      # Synced registries in an ID range that have no blob location yet
      #
      # @param [Range] range registry IDs
      # @return [Hash] registry ID by model record ID
      def synced_without_blob_location(range)
        synced.where(id: range, blob_path: nil).limit(range.size).pluck(model_foreign_key, :id).to_h
      end

      # Sets the blob location on registries that still have none, so a value written by a
      # concurrent sync wins. Sets uploader_class only on tables that have the column.
      #
      # @param [Array<Hash>] locations { id:, blob_path:, uploader_class: } per registry
      # @return [Integer] number of updated registries
      def fill_missing_blob_locations(locations)
        return 0 if locations.empty?

        with_uploader_class = column_names.include?('uploader_class')
        columns = with_uploader_class ? %w[blob_path uploader_class] : %w[blob_path]
        rows = locations.map do |location|
          values = [Integer(location[:id])] + columns.map { |column| connection.quote(location[column.to_sym]) }
          "(#{values.join(', ')})"
        end

        assignments = columns.map { |column| "#{column} = locations.#{column}" }.join(', ')

        connection.exec_update(<<~SQL, "#{name} fill blob locations")
          UPDATE #{quoted_table_name}
          SET #{assignments}
          FROM (VALUES #{rows.join(', ')}) AS locations(id, #{columns.join(', ')})
          WHERE #{quoted_table_name}.id = locations.id AND #{quoted_table_name}.blob_path IS NULL
        SQL
      end

      def for_model_record_id(id)
        find_or_initialize_by(model_foreign_key => id)
      end

      def declarative_policy_class
        'Geo::RegistryPolicy'
      end

      def registry_consistency_worker_enabled?
        replicator_class.replication_enabled?
      end

      # Fail syncs for records which started syncing a long time ago
      def fail_sync_timeouts
        attrs = {
          state: state_value(:failed),
          last_sync_failure: "Sync timed out after #{replicator_class.sync_timeout}",
          retry_count: 1,
          retry_at: next_retry_time(1)
        }

        sync_timed_out.all.each_batch do |relation|
          relation.update_all(attrs)
        end
      end
    end

    # Overridden by Geo::VerifiableRegistry
    def before_pending
      self.retry_at = nil
      self.retry_count = 0
    end

    # Overridden by Geo::VerifiableRegistry
    def before_started
      self.last_synced_at = Time.current
    end

    def before_synced
      self.retry_count = 0
      self.last_sync_failure = nil
      self.retry_at = nil
    end

    # Overridden by Geo::VerifiableRegistry
    def after_synced
      log_debug("Sync state transition", {
        registry_id: id, model_record_id: model_record_id, from: 'started', to: 'synced'
      })
    end

    def replicator_class
      Gitlab::Geo::Replicator.for_class_name(self)
    end

    included do
      include ::Delay

      attr_accessor :custom_max_retry_wait_time

      scope :failed, -> { with_state(:failed) }
      # SPIKE (gitlab-org/gitlab#602803): used by the Geo cleanup tools to find failed
      # registries whose sync failure matches a known-error pattern. It chains `failed` first
      # (an indexed `state` filter), so the free-text LIKE only runs over the failed rows, not
      # the whole table. The LIKE itself is not index-backed, which is fine for an on-demand
      # diagnostic but not for a frequent cron.
      scope :with_sync_failure_matching, ->(pattern) {
        failed.where(arel_table[:last_sync_failure].matches("%#{sanitize_sql_like(pattern)}%"))
      }
      scope :needs_sync_again, -> { failed.retry_due.order(arel_table[:retry_at].asc.nulls_first) }
      scope :pending, -> { with_state(:pending) }
      scope :not_pending, -> { without_state(:pending) }
      scope :retry_due, -> { where(arel_table[:retry_at].eq(nil).or(arel_table[:retry_at].lt(Time.current))) }
      scope :synced, -> { with_state(:synced) }
      scope :sync_timed_out, -> { with_state(:started).where(last_synced_at: ...replicator_class.sync_timeout.ago) }
      scope :unsynced, -> { without_state(:synced) }

      state_machine :state, initial: :pending do
        state :pending, value: STATE_VALUES[:pending]
        state :started, value: STATE_VALUES[:started]
        state :synced, value: STATE_VALUES[:synced]
        state :failed, value: STATE_VALUES[:failed]

        before_transition any => :started do |registry, _|
          registry.before_started
        end

        before_transition any => :pending do |registry, _|
          registry.before_pending
        end

        before_transition any => :failed do |registry, _|
          registry.retry_count += 1
          registry.retry_at = registry.next_retry_time(registry.retry_count, registry.custom_max_retry_wait_time)
        end

        # Transitions to synced usually do not go through this callback, see #synced!
        before_transition any => :synced do |registry, _|
          registry.before_synced
        end

        # Transitions to synced usually do not go through this callback, see #synced!
        after_transition any => :synced do |registry, _|
          registry.after_synced
        end

        after_transition any => [:pending, :started] do |registry, transition|
          registry.log_debug("Sync state transition",
            { registry_id: registry.id, model_record_id: registry.model_record_id,
              from: transition.from_name.to_s, to: transition.to_name.to_s, result: transition.result })
        end

        after_transition any => :failed do |registry, transition|
          registry.log_warning("Sync state transition",
            { registry_id: registry.id, model_record_id: registry.model_record_id,
              from: transition.from_name.to_s, to: transition.to_name.to_s, result: transition.result })
        end

        event :pending do
          transition [:pending, :started, :synced, :failed] => :pending
        end

        event :start do
          transition [:pending, :synced, :failed] => :started
        end

        event :failed do
          transition [:pending, :started, :synced, :failed] => :failed
        end

        event :resync do
          transition [:synced, :failed] => :pending
        end
      end

      # Override state machine failed! event method to record a failure message at
      # the same time.
      #
      # @param [String] message error information
      # @param [StandardError] error exception
      # @param [Boolean] missing_on_primary if the resource is missing on the primary
      def failed!(message:, error: nil, missing_on_primary: nil)
        self.last_sync_failure = message
        self.last_sync_failure += ": #{error.message}" if error.respond_to?(:message)
        self.last_sync_failure = self.last_sync_failure.truncate(255)
        self.custom_max_retry_wait_time = missing_on_primary ? 4.hours : nil

        super()
      end

      # Override state machine synced! event method to indicate that the sync
      # succeeded (but separately mark as synced atomically).
      #
      # @return [Boolean] whether the update was successful
      def synced!
        before_synced
        save!

        return false unless mark_synced_atomically

        after_synced

        true
      end

      # Mark the resource as synced using atomic conditions
      #
      # @return [Boolean] whether the update was successful
      def mark_synced_atomically
        # We can only update registry if state is started.
        # If state is set to pending that means that pending! was called
        # during the sync so we need to reschedule new sync
        num_rows = self.class
                       .where(self.class.model_foreign_key => model_record_id)
                       .with_state(:started)
                       .update_all(state: Geo::ReplicableRegistry::STATE_VALUES[:synced])

        num_rows > 0
      end

      def replicator
        self.class.replicator_class.new(model_record_id: model_record_id)
      end
    end
  end
end
