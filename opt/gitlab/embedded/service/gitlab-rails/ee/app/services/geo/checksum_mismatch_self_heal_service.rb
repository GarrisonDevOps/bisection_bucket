# frozen_string_literal: true

module Geo
  # Acts on checksum-mismatch failures reported by a secondary (see
  # Geo::ChecksumMismatchReportingService) by marking the primary's own
  # verification state back to `verification_pending` for resources that are
  # eligible for self-heal re-verification.
  #
  # Trust boundary: the request originates from a secondary over the Geo API,
  # so entries are treated as untrusted. A record is only re-verified when the
  # primary can independently confirm it is worth doing - see `#eligible?`.
  # Flipping an eligible record to `verification_pending` removes it from the
  # succeeded/failed candidate set, so concurrent or duplicate reports for the
  # same record are naturally no-ops.
  class ChecksumMismatchSelfHealService
    include ::Gitlab::Geo::LogHelpers

    SUCCEEDED = ::Geo::VerificationState::VERIFICATION_STATE_VALUES[:verification_succeeded]
    FAILED = ::Geo::VerificationState::VERIFICATION_STATE_VALUES[:verification_failed]

    def initialize(geo_node_id:, failures:)
      @geo_node_id = geo_node_id
      @failures = failures
    end

    def execute
      return 0 unless ::Gitlab::Geo.primary?
      return 0 unless enabled?

      failures.group_by { |failure| failure[:replicable_name] }.sum do |replicable_name, entries|
        heal_replicable(replicable_name, entries)
      end
    end

    private

    attr_reader :geo_node_id, :failures

    def enabled?
      ::Feature.enabled?(:geo_self_heal_checksum_mismatch, :instance, type: :ops)
    end

    def heal_replicable(replicable_name, entries)
      replicator_class = ::Gitlab::Geo::Replicator.for_replicable_name(replicable_name)
      model = replicator_class.model
      by_id = entries.index_by { |entry| entry[:replicable_id] }

      records_for(model, by_id.keys).sum { |record| heal_record(record, by_id[record.id]) ? 1 : 0 }
    rescue NotImplementedError
      log_info('Unknown replicable_name reported for checksum mismatch self-heal', replicable_name: replicable_name)
      0
    end

    # rubocop:disable CodeReuse/ActiveRecord -- resolving the replicator's model dynamically by replicable_name, so there is no model class to place this on
    def records_for(model, ids)
      scope = model.where(model.primary_key => ids)
      scope = scope.includes(model.active_record_state_association.name) if model.separate_verification_state_table?
      scope
    end
    # rubocop:enable CodeReuse/ActiveRecord

    def heal_record(record, entry)
      state = record.verification_state_object
      return false unless eligible?(state, entry)

      state.verification_pending!

      log_info(
        'Marked primary record as pending checksum re-verification',
        replicable_name: entry[:replicable_name],
        replicable_id: entry[:replicable_id],
        geo_node_id: geo_node_id
      )

      true
    end

    def eligible?(state, entry)
      return false unless [SUCCEEDED, FAILED].include?(state.verification_state)

      # Failed records have no trustworthy checksum (it's cleared on
      # failure), so they are always eligible to be re-verified.
      return true if state.verification_state == FAILED

      # Succeeded records are only re-verified if the primary's checksum
      # hasn't already changed since the secondary's report, and are
      # throttled so the same resource isn't repeatedly recomputed while its
      # checksum has already been recently confirmed.
      state.verification_checksum.to_s == reported_checksum(entry).to_s &&
        (state.verified_at.nil? || state.verified_at < cooldown.ago)
    end

    def reported_checksum(entry)
      (entry[:context] || {})[:primary_checksum_at_mismatch]
    end

    # Throttled using the primary's own setting: the primary is what enforces
    # the cooldown, regardless of which secondary reported the mismatch.
    def cooldown
      ::Gitlab::Geo.current_node&.checksum_mismatch_self_heal_cooldown_minutes.to_i.minutes
    end
  end
end
