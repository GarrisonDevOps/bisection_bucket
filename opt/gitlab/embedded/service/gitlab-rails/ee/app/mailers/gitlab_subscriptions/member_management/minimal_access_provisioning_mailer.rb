# frozen_string_literal: true

module GitlabSubscriptions
  module MemberManagement
    class MinimalAccessProvisioningMailer < ApplicationMailer
      helper EmailsHelper

      layout 'mailer'

      def notify_group_owner(namespace:, recipient:, user_count:, sync_date:)
        @namespace = namespace
        @recipient = recipient
        @user_count = user_count
        @sync_date = sync_date

        @restricted_access_help_url = help_page_url('subscriptions/manage_seats.md', anchor: 'restricted-access')
        @members_url = group_group_members_url(@namespace)
        @seat_usage_help_url = help_page_url('subscriptions/manage_seats.md', anchor: 'view-seat-usage')

        common_help_pages

        notify(recipient.email)
      end

      def notify_instance_admin(recipient:, user_count:, sync_date:)
        @recipient = recipient
        @user_count = user_count
        @sync_date = sync_date

        @restricted_access_help_url = help_page_url('subscriptions/manage_seats.md',
          anchor: 'restricted-access'
        )
        @users_url = admin_users_url
        @seat_usage_help_url = help_page_url(
          'subscriptions/manage_subscription.md', anchor: 'for-gitlab-self-managed-1'
        )

        common_help_pages

        notify(recipient.email)
      end

      private

      def notify(email)
        mail_with_locale(
          to: email,
          subject: s_(
            'MinimalAccessProvisioning|Action required: Users assigned Minimal Access role due to seat constraints'
          )
        )
      end

      def common_help_pages
        @minimal_access_help_url = help_page_url('user/permissions.md', anchor: 'users-with-minimal-access')
        @purchase_seats_help_url = help_page_url('subscriptions/manage_seats.md', anchor: 'buy-more-seats')
      end
    end
  end
end
