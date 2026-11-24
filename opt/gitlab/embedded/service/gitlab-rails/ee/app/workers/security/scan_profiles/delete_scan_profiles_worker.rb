# frozen_string_literal: true

module Security
  module ScanProfiles
    class DeleteScanProfilesWorker
      include ApplicationWorker
      include Gitlab::ExclusiveLeaseHelpers

      LEASE_TTL = 5.minutes
      LEASE_TRY_AFTER = 3.seconds

      idempotent!
      data_consistency :sticky
      feature_category :security_testing_configuration
      deduplicate :until_executing, including_scheduled: true

      def perform(scan_profile_ids, namespace_id = nil)
        return if scan_profile_ids.empty?

        if namespace_id
          delete_with_lock(scan_profile_ids, namespace_id)
        else
          delete_scan_profiles(scan_profile_ids)
        end
      end

      private

      def delete_with_lock(scan_profile_ids, namespace_id)
        lease_key = Security::ScanProfiles.update_lease_key(namespace_id)

        in_lock(lease_key, ttl: LEASE_TTL, sleep_sec: LEASE_TRY_AFTER) do
          delete_scan_profiles(scan_profile_ids)
        end
      end

      def delete_scan_profiles(scan_profile_ids)
        scan_profile_ids.each do |scan_profile_id|
          DeleteScanProfileService.execute(scan_profile_id)
        end
      end
    end
  end
end
