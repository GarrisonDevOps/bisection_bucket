# frozen_string_literal: true

module Geo
  module VerifiableReplicator
    extend ActiveSupport::Concern

    include Delay

    DEFAULT_VERIFICATION_BATCH_SIZE = 10
    DEFAULT_REVERIFICATION_BATCH_SIZE = 1000
    # Reduced from 10000 to 1000 to further mitigate
    # https://gitlab.com/gitlab-org/gitlab/-/issues/429242
    # in combination with
    # https://gitlab.com/gitlab-org/gitlab/-/merge_requests/136275
    DEFAULT_VERIFICATION_STATE_BACKFILL_BATCH_SIZE = 1000

    included do
      event :checksum_succeeded
    end

    class_methods do
      extend Gitlab::Utils::Override

      delegate :verification_pending_batch,
        :verification_failed_batch,
        :needs_verification_count,
        :needs_reverification_count,
        :fail_verification_timeouts,
        :reverifiable_batch,
        :reverify_batch,
        to: :verification_query_class

      override :verification_enabled?
      def verification_enabled?
        return primary_checksumming_enabled? if ::Gitlab::Geo.primary?
        return secondary_verification_enabled? if ::Gitlab::Geo.secondary_or_org_migration_target?

        false
      end

      # Called every minute by VerificationCronWorker
      def trigger_background_verification
        return false unless verification_enabled?

        ::Geo::VerificationBatchWorker.perform_with_capacity(replicable_name)
        ::Geo::VerificationTimeoutWorker.perform_async(replicable_name)

        # Secondaries don't need to run this since they will receive an event for each
        # rechecksummed resource: https://gitlab.com/gitlab-org/gitlab/-/issues/13842
        return unless ::Gitlab::Geo.primary?

        ::Geo::ReverificationBatchWorker.perform_with_capacity(replicable_name)

        return unless verification_query_class.separate_verification_state_table?

        ::Geo::VerificationStateBackfillWorker.perform_async(replicable_name)
      end

      # Called by VerificationBatchWorker.
      #
      # - Gets next batch of records that need to be verified
      # - Verifies them
      #
      def verify_batch
        replicator_batch_to_verify.each(&:verify)
      end

      # Called by VerificationBatchWorker.
      #
      # - Asks the DB how many things still need to be verified (with a limit)
      # - Converts that to a number of batches
      #
      # @return [Integer] number of batches of verification work remaining, up to the given maximum
      def remaining_verification_batch_count(max_batch_count:)
        needs_verification_count(limit: max_batch_count * verification_batch_size)
          .fdiv(verification_batch_size)
          .ceil
      end

      # Called by ReverificationBatchWorker.
      #
      # - Asks the DB how many things still need to be reverified (with a limit)
      # - Converts that to a number of batches
      #
      # @return [Integer] number of batches of reverification work remaining, up to the given maximum
      def remaining_reverification_batch_count(max_batch_count:)
        needs_reverification_count(limit: max_batch_count * reverification_batch_size)
          .fdiv(reverification_batch_size)
          .ceil
      end

      # @return [Array<Gitlab::Geo::Replicator>] batch of replicators which need to be verified
      def replicator_batch_to_verify
        model_record_id_batch_to_verify.map do |id|
          new(model_record_id: id)
        end
      end

      # @return [Array<Integer>] list of IDs for this replicator's model which need to be verified
      def model_record_id_batch_to_verify
        ids = verification_pending_batch(batch_size: verification_batch_size)

        remaining_batch_size = verification_batch_size - ids.size

        ids += verification_failed_batch(batch_size: remaining_batch_size) if remaining_batch_size > 0

        ids
      end

      # @return [Integer] number of records set to be re-verified
      def reverify_batch!
        reverify_batch(batch_size: reverification_batch_size)
      end

      # Gets the next batch of rows from the replicable table, and inserts and
      # deletes corresponding rows in the verification state table.
      #
      # @return [Boolean] whether any rows needed to be inserted or deleted
      def backfill_verification_state_table
        return false unless Gitlab::Geo.primary?
        return false unless verification_enabled?

        Geo::VerificationStateBackfillService.new(model, batch_size: verification_state_backfill_batch_size).execute
      rescue StandardError => e
        log_error("Error while updating verifiables", e)

        raise
      end

      # If primary, query the model table.
      # If secondary or org migration target, query the registry table.
      def verification_query_class
        Gitlab::Geo.secondary_or_org_migration_target? ? registry_class : model
      end

      # @return [Integer] number of records to verify per batch job
      def verification_batch_size
        DEFAULT_VERIFICATION_BATCH_SIZE
      end

      # @return [Integer] number of records to reverify per batch job
      def reverification_batch_size
        DEFAULT_REVERIFICATION_BATCH_SIZE
      end

      # @return [Integer] number of records to check for backfill per batch job
      def verification_state_backfill_batch_size
        DEFAULT_VERIFICATION_STATE_BACKFILL_BATCH_SIZE
      end

      # Overrides Gitlab::Geo::Replicator.primary_total_count to avoid the
      # expensive scoped MAX(id) that Gitlab::Database::BatchCounter computes
      # internally when no finish value is given. When available_replicables
      # filters or joins a large table (for example MergeRequestDiff's
      # has_external_diffs), that scoped MAX is a sequential scan. Passing
      # max_key (the unscoped primary-key MAX, served by the PK index) lets
      # BatchCounter use it as the finish bound instead.
      # See https://gitlab.com/gitlab-org/gitlab/-/issues/598940.
      override :primary_total_count
      def primary_total_count
        model_batch_count(model.available_replicables, column: model_column, max_key: model_max_primary_key) do
          model.available_replicables.count
        end
      end

      def checksummed_count
        # When verification is disabled, this returns nil.
        # Bonus: This causes the progress bar to be hidden.
        return unless verification_enabled?

        model_batch_count(model.verification_succeeded, column: model_column, max_key: model_max_primary_key) do
          model.verification_succeeded.count
        end
      end

      def checksum_failed_count
        # When verification is disabled, this returns nil.
        # Bonus: This causes the progress bar to be hidden.
        return unless verification_enabled?

        model_batch_count(model.verification_failed, column: model_column, max_key: model_max_primary_key) do
          model.verification_failed.count
        end
      end

      def checksum_total_count
        # When verification is disabled, this returns nil.
        # Bonus: This causes the progress bar to be hidden.
        return unless verification_enabled?

        model_batch_count(model.available_verifiables, column: model_column, max_key: model_max_primary_key) do
          model.available_verifiables.count
        end
      end

      def verified_count
        # When verification is disabled, this returns nil.
        # Bonus: This causes the progress bar to be hidden.
        return unless verification_enabled?

        batch_count(registry_class.verification_succeeded, registry_class.primary_key) do
          registry_class.verification_succeeded.count
        end
      end

      def verification_failed_count
        # When verification is disabled, this returns nil.
        # Bonus: This causes the progress bar to be hidden.
        return unless verification_enabled?

        batch_count(registry_class.verification_failed, registry_class.primary_key) do
          registry_class.verification_failed.count
        end
      end

      def verification_total_count
        # When verification is disabled, this returns nil.
        # Bonus: This causes the progress bar to be hidden.
        return unless verification_enabled?

        # Exclude resources where verification is disabled. We need to do
        # frontend work if we want to show admins verification_disabled things.
        batch_count(registry_class.verification_not_disabled, registry_class.primary_key) do
          registry_class.verification_not_disabled.count
        end
      end

      private

      def primary_checksumming_enabled?
        # If replication is enabled on the primary, then the
        # verification must be enabled. This way, we can verify
        # the data on the secondary sites.
        return true if replication_enabled?

        force_primary_checksumming_enabled?
      end

      def secondary_verification_enabled?
        # If replication is disabled on the primary, then the
        # verification is also disabled on the secondary since
        # it will not have the data to verify.
        replication_enabled?
      end

      def force_primary_checksumming_enabled?
        Feature.enabled?(force_primary_checksumming_feature_key, :instance, type: :ops)
      end

      def force_primary_checksumming_feature_key
        :"geo_#{replicable_name}_force_primary_checksumming"
      end

      def model_max_primary_key
        model.maximum(model_column)
      end

      def model_column
        @model_column ||= model.primary_key
      end
    end

    def geo_handle_after_checksum_succeeded
      return unless Gitlab::Geo.primary?
      return unless self.class.verification_enabled?

      publish(:checksum_succeeded, **event_params)
    end

    # Called by Gitlab::Geo::Replicator#consume
    def consume_event_checksum_succeeded(**_params)
      return unless Gitlab::Geo.secondary_or_org_migration_target?
      return unless registry.persisted?

      registry.verification_pending!
    end

    def verify_async
      # Just let verification backfill pick it up to ensure
      # the verification concurrency limit is applied to all
      # create and update events.
      #
      # See issue: https://gitlab.com/gitlab-org/gitlab/-/issues/443875
      verification_state_tracker.verification_pending!
    end

    # Calculates checksum and asks the model/registry to manage verification
    # state.
    def verify
      verification_state_tracker.track_checksum_attempt! do
        calculate_checksum
      end
    end

    # Check if given checksum matches known one
    #
    # @param [String] checksum
    # @return [Boolean] whether checksum matches
    def matches_checksum?(checksum)
      primary_checksum == checksum
    end

    # Checksum value from the main database
    #
    # @abstract
    def primary_checksum
      # If verification is not yet setup, then model_record will not have the verification_checksum
      # attribute yet. Returning nil is fine here
      model_record.verification_checksum if model_record.respond_to?(:verification_checksum)
    end

    def primary_verified_at
      model_record.verified_at if model_record.respond_to?(:verified_at)
    end

    def verification_state_tracker
      Gitlab::Geo.secondary_or_org_migration_target? ? registry : model_record
    end

    # For example, remote stored files will never become verification_succeeded
    # until verification of remote stored files is implemented.
    def primary_verification_succeeded?
      model_record.verification_succeeded?
    end

    # When starting to sync something for the first time, sometimes we find it
    # is already synced. In certain cases, we don't need to download it. We can
    # instead rely on verification to trigger a resync if needed.
    #
    # For example, a replicable may legitimately already be synced if:
    #
    # - you did a planned failover and attached the old primary as a
    #   secondary without rebuilding it.
    # - you did a failover test on a secondary, rewound the PG DB, and
    #   reattached it without rebuilding it.
    # - you restored a backup and attached the site as a secondary
    # - you manually copied the replicable to a secondary to workaround a problem
    # - you reset the Geo tracking database to workaround a problem
    #
    # @return [Boolean] whether it is a good idea to mark a replicable synced without downloading it
    def ok_to_skip_download?
      # Verification of immutable data is likely to pass if the data seems to
      # already exist. We are much less sure about mutable data, so let's
      # exclude it from this optimization for now.
      return false if mutable?

      # It is crucial that we do not skip downloading if a "resync" is intended,
      # e.g. if an admin clicked "Resync". So only skip if the registry record
      # looks like a brand-new pending registry record.
      return false unless registry.brand_new_pending?

      # If data already exists at the expected location, and if we will verify
      # that data shortly after marking it synced, then it is relatively safe to
      # mark it synced without (re)downloading it.
      resource_exists? && skip_download_can_rely_on_verification?
    end

    # Downloading replicators need to verify the state of the resource and its association
    # prior to attempting downloads to avoid triggering exceptions. Call this method
    # to trigger validation and receive an error detail message string if any issues are present.
    #
    # Override this method in subclasses to provide more context-specific error details
    #
    # NOTE: we've kept this implementation pretty simple so far for the sake of
    #       detecting problems with replicating Upload and other blob data types.
    #       If we find later that we need to add this more extensively, or detect
    #       multiple errors (ala ActiveRecord models), we should revisit and refactor
    #       this implementation
    #
    # @return [String|nil] an error message String if validation fails, nil if validation succeeds
    def predownload_validation_failure
      nil
    end

    # @abstract
    # @return [String] a checksum representing the data
    def calculate_checksum
      raise NotImplementedError, "#{self.class} does not implement #{__method__}"
    end

    # @abstract
    # @return [Boolean] whether the replicable is supposed to be immutable
    def immutable?
      raise NotImplementedError, "#{self.class} does not implement #{__method__}"
    end

    def mutable?
      !immutable?
    end

    private

    def should_primary_verify_after_save?
      return false unless self.class.verification_enabled?

      # Optimization: If the data is immutable, then there is no need to
      # recalculate checksum when a record is created (some models calculate
      # checksum as part of creation) or updated. Note that reverification
      # should still run as usual.
      return false if immutable? && primary_checksum.present?

      checksummable?
    end

    # Return whether the replicable is capable of checksumming itself
    #
    # @return [Boolean] whether the replicable is capable of checksumming itself
    def checksummable?
      model_record.in_verifiables? && resource_exists?
    end

    # @return [Boolean] whether the file will be verified later if we were to skip download now
    def skip_download_can_rely_on_verification?
      self.class.verification_enabled? && checksummable?
    end
  end
end
