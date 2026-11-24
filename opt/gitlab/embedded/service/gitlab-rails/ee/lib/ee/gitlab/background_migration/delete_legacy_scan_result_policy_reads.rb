# frozen_string_literal: true

module EE
  module Gitlab
    module BackgroundMigration
      module DeleteLegacyScanResultPolicyReads
        extend ::Gitlab::Utils::Override

        RESYNC_SPREAD = 6.hours.to_i

        private

        # A regular sync either writes the missing security_policies rows, or, for invalid policy YAML,
        # deletes all reads of the configuration. A later run can then judge the reads it skipped.
        override :resync_configurations
        def resync_configurations(configuration_ids)
          configuration_ids.each do |id|
            # Fixed per-configuration offset spreads the resync burst across jobs, to keep policy sync load flat.
            ::Security::SyncScanPoliciesWorker.perform_in((id % RESYNC_SPREAD).seconds, id)
          end
        end
      end
    end
  end
end
