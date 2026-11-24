# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class SyncProjectWorker
      include ApplicationWorker

      data_consistency :delayed

      deduplicate :until_executing, including_scheduled: true
      idempotent!

      feature_category :security_policy_management

      DELAY_INTERVAL = 30.seconds.to_i

      def perform(project_id)
        # no-op - scan result policy processing via YAML was deprecated after issue https://gitlab.com/gitlab-org/gitlab/-/issues/543955
      end
    end
  end
end
