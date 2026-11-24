# frozen_string_literal: true

#
# Used by NotificationService to determine who should receive notification
#
module NotificationRecipients
  module BuildService
    def self.notifiable_users(users, *args)
      recipients = users.compact.map { |u| NotificationRecipient.new(u, *args) }
      preload_notification_settings(recipients)
      notifiable_users = recipients.select(&:notifiable?).map(&:user)
      recipients.each { |recipient| recipient.user.association(:notification_settings).reset }
      notifiable_users
    end

    def self.preload_notification_settings(recipients)
      return if recipients.empty?

      ActiveRecord::Associations::Preloader.new(
        records: recipients.map(&:user), associations: [:notification_settings],
        scope: NotificationSetting.by_sources(recipients.first.notification_setting_sources)
      ).call
    end
    private_class_method :preload_notification_settings

    def self.notifiable?(user, *args)
      NotificationRecipient.new(user, *args).notifiable?
    end

    def self.build_recipients(target, current_user, **args)
      ::NotificationRecipients::Builder::Default.new(target, current_user, **args).notification_recipients
    end

    def self.build_new_note_recipients(...)
      ::NotificationRecipients::Builder::NewNote.new(...).notification_recipients
    end

    def self.build_merge_request_unmergeable_recipients(...)
      ::NotificationRecipients::Builder::MergeRequestUnmergeable.new(...).notification_recipients
    end

    def self.build_project_maintainers_recipients(target, **args)
      ::NotificationRecipients::Builder::ProjectMaintainers.new(target, **args).notification_recipients
    end

    def self.build_new_review_recipients(...)
      ::NotificationRecipients::Builder::NewReview.new(...).notification_recipients
    end

    def self.build_requested_review_recipients(...)
      ::NotificationRecipients::Builder::RequestReview.new(...).notification_recipients
    end
  end
end

NotificationRecipients::BuildService.prepend_mod
