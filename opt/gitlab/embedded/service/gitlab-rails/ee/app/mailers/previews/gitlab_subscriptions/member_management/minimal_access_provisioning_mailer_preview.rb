# frozen_string_literal: true

module GitlabSubscriptions
  module MemberManagement
    class MinimalAccessProvisioningMailerPreview < ActionMailer::Preview
      def notify_group_owner
        ::GitlabSubscriptions::MemberManagement::MinimalAccessProvisioningMailer.notify_group_owner(
          namespace: Group.last.root_ancestor,
          recipient: User.last,
          user_count: 10,
          sync_date: Date.yesterday.iso8601
        ).message
      end

      def notify_instance_admin
        ::GitlabSubscriptions::MemberManagement::MinimalAccessProvisioningMailer.notify_instance_admin(
          recipient: User.last,
          user_count: 10,
          sync_date: Date.yesterday.iso8601
        ).message
      end
    end
  end
end
