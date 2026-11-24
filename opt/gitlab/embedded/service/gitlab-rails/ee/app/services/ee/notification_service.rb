# frozen_string_literal: true

module EE
  module NotificationService
    include ::Gitlab::Utils::UsageData
    extend ::Gitlab::Utils::Override

    def mirror_was_hard_failed(project)
      return if project.emails_disabled?

      owners_and_maintainers_without_invites(project).each do |recipient|
        mailer.mirror_was_hard_failed_email(project.id, recipient.user.id).deliver_later
      end
    end

    def mirror_was_disabled(project, deleted_user_name)
      return if project.emails_disabled?

      owners_and_maintainers_without_invites(project).each do |recipient|
        mailer.mirror_was_disabled_email(project.id, recipient.user.id, deleted_user_name).deliver_later
      end
    end

    def new_epic(epic, current_user)
      new_resource_email(epic, current_user, :new_epic_email)
    end

    def close_epic(epic, current_user)
      epic_status_change_email(epic, current_user, 'closed')
    end

    def reopen_epic(epic, current_user)
      epic_status_change_email(epic, current_user, 'reopened')
    end

    def removed_iteration_issue(issue, current_user)
      removed_iteration_resource_email(issue, current_user)
    end

    def changed_iteration_issue(issue, new_iteration, current_user)
      changed_iteration_resource_email(issue, new_iteration, current_user)
    end

    def notify_oncall_users_of_alert(users, alert)
      track_usage_event(:i_incident_management_oncall_notification_sent, users.map(&:id))

      users.each do |user|
        mailer.prometheus_alert_fired_email(alert.project, user, alert).deliver_later
      end
    end

    def notify_oncall_users_of_incident(users, issue)
      track_usage_event(:i_incident_management_oncall_notification_sent, users.map(&:id))

      users.each do |user|
        mailer.incident_escalation_fired_email(issue.project, user, issue).deliver_later
      end
    end

    def oncall_user_removed(rotation, user, async_notification = true)
      oncall_user_removed_recipients(rotation, user).each do |recipient|
        email = mailer.user_removed_from_rotation_email(user, rotation, [recipient])

        async_notification ? email.deliver_later : email.deliver_now
      end
    end

    def user_escalation_rule_deleted(project, user, rules)
      user_escalation_rule_deleted_recipients(project, user).map do |recipient|
        # Deliver now as rules (& maybe user) are being deleted
        mailer.user_escalation_rule_deleted_email(user, project, rules, recipient).deliver_now
      end
    end

    def added_as_approver(recipients, merge_request)
      recipients = notifiable_users(recipients, :custom, custom_action: :approver, project: merge_request.project)

      recipients.each do |recipient|
        mailer.added_as_approver_email(
          recipient.id,
          merge_request.id,
          merge_request.author.id
        ).deliver_later
      end

      ::TodoService.new.added_approver(recipients, merge_request)
    end

    def no_more_seats(namespace, recipients, user, requested_member_list)
      namespace_limit = namespace.namespace_limit

      updated = namespace_limit.with_lock do
        all_seats_used_notification_at = namespace_limit.last_seat_all_used_seats_notification_at

        next unless all_seats_used_notification_at.nil? || all_seats_used_notification_at < 1.day.ago

        namespace_limit.update!(last_seat_all_used_seats_notification_at: Time.current)
      end

      return unless updated

      recipients.each do |recipient|
        ::Notify.no_more_seats(recipient.id, user.id, namespace, requested_member_list).deliver_later
      end
    end

    def pipeline_finished(pipeline, ref_status: nil, recipients: nil)
      return if super.nil? || !pipeline.user&.service_account? || recipients.present?

      status = pipeline_notification_status(ref_status, pipeline)
      email_template = email_template_name(status)

      recipients = NotificationRecipients::BuildService
        .build_service_account_recipients(pipeline.project, pipeline.user, status)

      recipients.each do |recipient|
        mailer.public_send(email_template, pipeline, recipient.notification_email).deliver_later # rubocop:disable GitlabSecurity/PublicSend -- not a security issue
      end
    end

    def secret_rotation_reminder_for_project(rotation_info)
      project = rotation_info.project
      recipients = owners_without_invites(project)

      recipients.each do |recipient|
        mailer.project_secret_rotation_reminder_email(
          recipient.id,
          project.id,
          rotation_info.secret_name
        ).deliver_later
      end
    end

    def secret_rotation_reminder_for_group(rotation_info)
      group = rotation_info.group
      recipients = group.members.active_without_invites_and_requests.owners.map(&:user)

      recipients.each do |recipient|
        mailer.group_secret_rotation_reminder_email(
          recipient.id,
          group.id,
          rotation_info.secret_name
        ).deliver_later
      end
    end

    def ai_flow_schedule_deactivated(schedule)
      return if schedule.project.emails_disabled?

      owners_and_maintainers_without_invites(schedule.project).preload_users.each do |recipient|
        next unless Ability.allowed?(recipient.user, :receive_notifications)

        mailer.ai_flow_schedule_deactivated_email(schedule, recipient.user).deliver_later
      end
    end

    def ai_flow_schedule_failed(schedule)
      return if schedule.project.emails_disabled?

      owners_and_maintainers_without_invites(schedule.project).preload_users.each do |recipient|
        next unless Ability.allowed?(recipient.user, :receive_notifications)

        mailer.ai_flow_schedule_failure_email(schedule, recipient.user).deliver_later
      end
    end

    private

    def oncall_user_removed_recipients(rotation, removed_user)
      incident_management_owners(rotation.project)
       .including(rotation.participating_users)
       .excluding(removed_user)
       .uniq
    end

    def user_escalation_rule_deleted_recipients(project, removed_user)
      incident_management_owners(project).excluding(removed_user)
    end

    def incident_management_owners(project)
      return project.owners if project.personal?

      ::MembersFinder
        .new(project, nil, params: { active_without_invites_and_requests: true })
        .execute
        .owners
        .map(&:user)
    end

    def removed_iteration_resource_email(target, current_user)
      recipients = ::NotificationRecipients::BuildService.build_recipients(
        target,
        current_user,
        action: 'removed_iteration'
      )

      recipients.each do |recipient|
        mailer.removed_iteration_issue_email(recipient.user.id, target.id, current_user.id).deliver_later
      end
    end

    def changed_iteration_resource_email(target, iteration, current_user)
      recipients = ::NotificationRecipients::BuildService.build_recipients(
        target,
        current_user,
        action: 'changed_iteration'
      )

      recipients.each do |recipient|
        mailer.changed_iteration_issue_email(recipient.user.id, target.id, iteration, current_user.id).deliver_later
      end
    end

    def epic_status_change_email(target, current_user, status)
      action = status == 'reopened' ? 'reopen' : 'close'

      recipients = ::NotificationRecipients::BuildService.build_recipients(
        target,
        current_user,
        action: action
      )

      recipients.each do |recipient|
        mailer.epic_status_changed_email(
          recipient.user.id, target.id, status, current_user.id, recipient.reason)
          .deliver_later
      end
    end
  end
end
