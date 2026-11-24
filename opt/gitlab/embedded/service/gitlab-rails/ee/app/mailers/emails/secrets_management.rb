# frozen_string_literal: true

module Emails # rubocop:disable Gitlab/BoundedContexts -- This is following current patterns
  module SecretsManagement
    def project_secret_rotation_reminder_email(user_id, project_id, secret_name)
      @user = User.find(user_id)
      @project = Project.find(project_id)
      @secret_name = secret_name

      @target_url = project_secrets_url(@project, anchor: "/#{@secret_name}/details")

      email_with_layout(
        to: @user.notification_email_for(@project.group),
        subject: subject(s_('SecretRotation|Secret rotation reminder'))
      )
    end

    def group_secret_rotation_reminder_email(user_id, group_id, secret_name)
      @user = User.find(user_id)
      @group = Group.find(group_id)
      @secret_name = secret_name

      @target_url = group_secrets_url(@group, anchor: "/#{@secret_name}/details")

      email_with_layout(
        to: @user.notification_email_for(@group),
        subject: subject(s_('SecretRotation|Secret rotation reminder'))
      )
    end
  end
end
