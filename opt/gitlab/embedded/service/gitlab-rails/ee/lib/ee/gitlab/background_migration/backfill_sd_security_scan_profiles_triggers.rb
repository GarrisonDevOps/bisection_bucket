# frozen_string_literal: true

module EE
  module Gitlab
    module BackgroundMigration
      module BackfillSdSecurityScanProfilesTriggers
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        SECRET_DETECTION_SCAN_TYPE = 1

        TRIGGER_TYPES = [0, 1].freeze # default_branch_pipeline, merge_request_pipeline

        class ScanProfile < ::SecApplicationRecord
          self.table_name = 'security_scan_profiles'
        end

        class ScanProfileTrigger < ::SecApplicationRecord
          self.table_name = 'security_scan_profile_triggers'
        end

        prepended do
          operation_name :backfill_sd_security_scan_profiles_triggers
          feature_category :security_asset_inventories
        end

        override :perform
        def perform
          each_sub_batch do |sub_batch|
            profiles = sub_batch.where(scan_type: SECRET_DETECTION_SCAN_TYPE, gitlab_recommended: true)
            next if profiles.empty?

            records = build_trigger_records(profiles)
            insert_triggers(records)
          end
        end

        private

        def build_trigger_records(profiles)
          current_time = Time.current

          profiles.flat_map do |profile|
            TRIGGER_TYPES.map do |trigger_type|
              {
                security_scan_profile_id: profile.id,
                namespace_id: profile.namespace_id,
                trigger_type: trigger_type,
                created_at: current_time,
                updated_at: current_time
              }
            end
          end
        end

        def insert_triggers(records)
          ScanProfileTrigger.insert_all(records, unique_by: [:security_scan_profile_id, :trigger_type])
        end
      end
    end
  end
end
