# frozen_string_literal: true

module EE
  module Gitlab
    module BackgroundMigration
      module BackfillSecurityScanProfilesNameAndDesc
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        SECRET_DETECTION_SCAN_TYPE = 1
        DEFAULT_PROFILE_NAME = 'Secret Detection (default)'
        DEFAULT_PROFILE_DESCRIPTION = "Protect your repository from leaked secrets like API keys, tokens, and " \
          "passwords. This profile uses industry-standard rules optimized to minimize false positives. " \
          "When enabled, secrets are detected in real time during git push events and blocked " \
          "before they're committed."

        prepended do
          operation_name :backfill_security_scan_profiles_name_and_desc
          feature_category :security_asset_inventories
        end

        override :perform
        def perform
          each_sub_batch do |sub_batch|
            sub_batch.where(scan_type: SECRET_DETECTION_SCAN_TYPE, gitlab_recommended: true).update_all(
              name: DEFAULT_PROFILE_NAME,
              description: DEFAULT_PROFILE_DESCRIPTION
            )
          end
        end
      end
    end
  end
end
