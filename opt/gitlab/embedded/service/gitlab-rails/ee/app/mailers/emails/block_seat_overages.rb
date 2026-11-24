# frozen_string_literal: true

module Emails
  module BlockSeatOverages
    def no_more_seats(recipient_id, user_id, project_or_group, requested_member_list = [])
      recipient = User.find_by_id(recipient_id)
      user = User.find_by_id(user_id)
      return if recipient.blank? || user.blank?

      @recipient_name = recipient.name
      @user_name = user.name
      @project_or_group = project_or_group
      @project_or_group_label = project_or_group.is_a?(Group) ? _('group') : _('project')
      @buy_seats_url = ::Gitlab::Routing.url_helpers.subscription_portal_add_extra_seats_url(@project_or_group.id)
      # TODO: to be provided later: see https://gitlab.com/gitlab-org/gitlab/-/issues/446061
      @subscription_info_url = ''
      @requested_member_list = requested_member_list

      email_with_layout(
        to: recipient.notification_email_or_default,
        subject: subject('Action required: Purchase more seats')
      )
    end

    def dormant_user_blocked_on_reactivation(recipient_id, blocked_user_id, group_id = nil)
      recipient = User.find_by_id(recipient_id)
      blocked_user = User.find_by_id(blocked_user_id)
      return if recipient.blank? || blocked_user.blank?

      @recipient_name = recipient.name
      @blocked_user_name = blocked_user.name
      @blocked_user_username = blocked_user.username
      @buy_seats_url = help_page_url('subscriptions/manage_seats.md', anchor: 'buy-more-seats')
      @view_seat_usage_url = help_page_url('subscriptions/manage_seats.md', anchor: 'view-seat-usage')
      @restricted_access_url = help_page_url('subscriptions/manage_seats.md', anchor: 'restricted-access')

      if group_id
        @group = Group.find_by_id(group_id)
        return if @group.blank?
      else
        @manage_users_url = ::Gitlab::Routing.url_helpers.admin_users_url
      end

      email_with_layout(
        to: recipient.notification_email_or_default,
        subject: subject(s_('AdminUsers|Action required: Dormant user blocked due to seat limits'))
      )
    end
  end
end
