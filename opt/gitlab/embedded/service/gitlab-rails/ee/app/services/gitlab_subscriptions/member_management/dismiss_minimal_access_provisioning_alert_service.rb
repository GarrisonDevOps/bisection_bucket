# frozen_string_literal: true

module GitlabSubscriptions
  module MemberManagement
    class DismissMinimalAccessProvisioningAlertService
      def initialize(current_user:, group: nil)
        @current_user = current_user
        @group = group
      end

      def execute
        if group
          ::GitlabSubscriptions::MemberManagement::SeatAwareProvisioning
            .record_group_count_at_dismissal(group, current_user)
        else
          ::GitlabSubscriptions::MemberManagement::SeatAwareProvisioning
            .record_instance_count_at_dismissal(current_user)
        end
      end

      private

      attr_reader :current_user, :group
    end
  end
end
