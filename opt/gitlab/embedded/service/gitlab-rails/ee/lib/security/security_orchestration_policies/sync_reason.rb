# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    module SyncReason
      REASONS = %i[policy_change force_resync configuration_assigned].freeze
      DEFAULT = :policy_change
      LEGACY_KEYS = { force_resync: 'force_resync', configuration_assigned: 'triggered_by_assign' }.freeze

      # Also sets the legacy boolean so a Sidekiq node still on the previous
      # release honors the reason. Drop the legacy key after one release:
      # https://gitlab.com/gitlab-org/gitlab/-/work_items/635126
      def self.to_params(reason)
        reason = reason.to_sym
        raise ArgumentError, "unknown sync_reason: #{reason}" unless REASONS.include?(reason)

        params = { 'sync_reason' => reason.to_s }
        legacy_key = LEGACY_KEYS[reason]
        params[legacy_key] = true if legacy_key
        params
      end

      # Jobs enqueued before sync_reason existed carry the force_resync and
      # triggered_by_assign booleans instead. Drop the fallback after one release:
      # https://gitlab.com/gitlab-org/gitlab/-/work_items/635126
      def self.from_params(params)
        params = (params || {}).with_indifferent_access
        reason = params[:sync_reason]&.to_sym

        return reason if REASONS.include?(reason)
        return :force_resync if params[:force_resync]
        return :configuration_assigned if params[:triggered_by_assign]

        DEFAULT
      end
    end
  end
end
