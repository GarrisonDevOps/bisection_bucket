# frozen_string_literal: true

module EE
  module Organizations
    module UpdateService
      extend ::Gitlab::Utils::Override

      override :execute
      def execute
        # Popped before super because the flag lives on the settings record,
        # not on the organization row super updates.
        opt_in = params.delete(:policy_store_experiment_enabled)

        # Only opting IN requires policy_store_experiment_available? to pass: a per-organization
        # flag check plus the instance-wide license and settings checks. Opting out is always
        # safe, so a lapsed license or disabled flag cannot strand an organization at enabled.
        # The permission check runs first so an unauthorized caller learns nothing about availability.
        if opt_in && allowed? && !organization.policy_store_experiment_available?
          return ServiceResponse.error(
            payload: { organization: organization },
            message: [_('Policy Store experiment is not available for this organization')]
          )
        end

        # One transaction, so a failed settings write also rolls back the
        # organization row and no partially-applied update can be observed.
        ::Organizations::OrganizationSetting.transaction do
          result = super

          write_policy_store_opt_in!(opt_in) unless result.error? || opt_in.nil?

          result
        end
      end

      private

      # A single upsert, not a find-then-write: merging the jsonb column on
      # conflict makes the first-write race impossible to observe, rather than
      # catching and retrying it (retrying would mean a subtransaction, which
      # Performance/ActiveRecordSubtransactions forbids: see
      # https://gitlab.com/gitlab-org/gitlab/-/issues/338346).
      def write_policy_store_opt_in!(opt_in)
        ::Organizations::OrganizationSetting.upsert(
          { organization_id: organization.id, settings: { policy_store_experiment_enabled: opt_in } },
          unique_by: :organization_id,
          on_duplicate: Arel.sql('settings = organization_settings.settings || excluded.settings')
        )
      end
    end
  end
end
