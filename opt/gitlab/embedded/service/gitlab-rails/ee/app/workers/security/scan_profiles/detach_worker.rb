# frozen_string_literal: true

module Security
  module ScanProfiles
    class DetachWorker
      include ApplicationWorker
      include Security::BackgroundOperationTracking

      data_consistency :sticky
      idempotent!
      deduplicate :until_executed

      concurrency_limit -> { 200 }

      feature_category :security_testing_configuration

      def perform(group_id, scan_profile_id, current_user_id, operation_id = nil, traverse_hierarchy = true)
        return unless load_resources(group_id, scan_profile_id, current_user_id)

        @operation_id = operation_id
        return unless operation_exists?

        result = Security::ScanProfiles::DetachService.execute(
          @group,
          @scan_profile,
          current_user: @user,
          traverse_hierarchy: traverse_hierarchy,
          operation_id: @operation_id
        )

        track_and_finalize(result) if @operation_id
      end

      private

      def load_resources(group_id, scan_profile_id, current_user_id)
        @group = Group.find_by_id(group_id)
        return false unless @group

        @scan_profile = Security::ScanProfile.not_deleted.find_by_id(scan_profile_id)
        return false unless @scan_profile

        @user = User.find_by_id(current_user_id)
        return false unless @user

        true
      end

      def track_and_finalize(result)
        if result[:status] == :success
          record_success
        else
          record_failure(@group, result[:message])
        end

        finalize_if_complete
      end
    end
  end
end
