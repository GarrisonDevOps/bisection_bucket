# frozen_string_literal: true

module Geo
  module VerifiableRegistry
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override
    include ::Geo::VerificationState
    include ::Geo::VerificationStateDefinition

    class_methods do
      extend ::Gitlab::Utils::Override

      # Overrides a method in `::Geo::VerificationState`. This method is
      # used by `::Geo::VerificationState.start_verification_batch` to
      # produce a query which must return values of the primary key of the
      # *model*, not of the *registry*. We need this so we can instantiate
      # Replicators.
      override :verification_state_model_key
      def verification_state_model_key
        model_foreign_key
      end
    end

    included do
      extend ::Gitlab::Utils::Override

      sha_attribute :verification_checksum_mismatched

      scope :available_verifiables, -> { synced }

      # Registries that have failed verification due to a checksum mismatch at
      # least `threshold` times in a row. Used to detect resources whose
      # persistent mismatch is likely caused by a stale checksum on the
      # primary, so they can be reported for self-heal re-verification.
      scope :persistent_checksum_mismatches, ->(threshold) {
        where(checksum_mismatch: true).where(verification_retry_count: threshold..)
      }

      override :clear_verification_failure_fields!
      def clear_verification_failure_fields!
        super

        # Force mismatch columns into UPDATE so a stale copy clears concurrent writes.
        # https://gitlab.com/gitlab-org/gitlab/-/work_items/627715
        checksum_mismatch_will_change!
        self.checksum_mismatch = false
        verification_checksum_mismatched_will_change!
        # Note: returning false from a before_transition callback halts the transition.
        self.verification_checksum_mismatched = nil
      end

      # Records a checksum mismatch
      #
      # @param [String] checksum value which does not match the primary checksum
      def verification_failed_due_to_mismatch!(checksum, primary_checksum)
        message = 'Checksum does not match the primary checksum'
        details = { checksum: checksum, primary_checksum: primary_checksum, registry_id: id }

        log_error(message, details)

        self.verification_failure = "#{message} #{details}".truncate(255)
        self.verification_checksum = checksum
        self.verification_checksum_mismatched = primary_checksum
        self.checksum_mismatch = true

        verification_failed!
      end

      def resync_due_to_out_of_date_copy!(checksum, primary_checksum)
        message = 'Checksum mismatch caused by primary update after sync, resyncing'
        details = { checksum: checksum, primary_checksum: primary_checksum, registry_id: id }

        log_info(message, details)

        clear_verification_failure_fields!

        pending!
      end

      override :track_checksum_attempt!
      def track_checksum_attempt!(&block)
        unless ready_to_verify?
          verification_disabled!
          return
        end

        super
      end

      def brand_new_pending?
        return false unless sync_fields_default_or_started?
        return false unless verification_fields_default?

        true
      end

      private

      override :track_checksum_result!
      def track_checksum_result!(checksum, calculation_started_at)
        current_replicator = replicator

        unless current_replicator.matches_checksum?(checksum)
          if primary_checksummed_after_last_sync?(current_replicator.primary_verified_at)
            return resync_due_to_out_of_date_copy!(checksum, current_replicator.primary_checksum)
          end

          return verification_failed_due_to_mismatch!(checksum, current_replicator.primary_checksum)
        end

        verification_succeeded_with_checksum!(checksum, calculation_started_at)
      end

      def primary_checksummed_after_last_sync?(primary_verified_at)
        primary_verified_at.present? &&
          last_synced_at.present? &&
          primary_verified_at > last_synced_at
      end

      def sync_fields_default_or_started?
        return false if !pending? && !started?

        # If pending, then last_synced_at must be nil
        return false if pending? && last_synced_at.present?

        retry_at.nil? &&
          last_sync_failure.blank? &&
          retry_count.to_i == 0
      end

      def verification_fields_default?
        verification_pending? &&
          verified_at.nil? &&
          verification_started_at.nil? &&
          verification_retry_at.nil? &&
          verification_checksum.nil? &&
          verification_checksum_mismatched.nil? &&
          verification_failure.blank? &&
          verification_retry_count.to_i == 0 &&
          [nil, false].include?(checksum_mismatch)
      end
    end

    override :before_pending
    def before_pending
      super

      verification_disabled
    end

    override :before_started
    def before_started
      # Capture this before super, which sets last_synced_at and would itself
      # flip brand_new_pending? to false.
      was_brand_new_pending = brand_new_pending?

      super

      # Keep verification_pending for a brand-new pending registry so the
      # skip-download optimization (ok_to_skip_download? -> brand_new_pending?)
      # still applies to first syncs. For any other state, disable verification
      # so the transition can be saved even from an invalid verification_failed
      # row (https://gitlab.com/gitlab-org/gitlab/-/issues/562921).
      verification_disabled unless was_brand_new_pending
    end

    override :after_synced
    def after_synced
      super

      unless ready_to_verify?
        verification_disabled!
        return
      end

      verification_pending!
    end

    def ready_to_verify?
      replicator.primary_verification_succeeded?
    end

    override :before_verification_failed
    def before_verification_failed
      # Let verification failure fields get set as usual
      super

      # When this registry became synced, retry_count was set to 0. This line
      # ensures that resyncs due to verification failures use progressive
      # backoff behavior. One is subtracted to compensate for 1 being
      # automatically added to `retry_count` on transition to failed.
      self.retry_count = verification_retry_count - 1

      self.last_sync_failure = "Verification failed with: #{verification_failure}".truncate(255)

      # This registry was successfully synced, and now it has failed
      # verification. This line makes Geo automatically resync it.
      failed
    end
  end
end
