# frozen_string_literal: true

module Emails # rubocop:disable Gitlab/BoundedContexts -- Existing module
  module VirtualRegistries
    def virtual_registry_cleanup_complete(policy, user)
      @policy = policy
      @user = user
      @group = policy.group

      email_with_layout(
        to: @user.notification_email_or_default,
        subject: subject_for_complete
      )
    end

    def virtual_registry_cleanup_failure(policy, user)
      @policy = policy
      @user = user
      @group = policy.group

      email_with_layout(
        to: @user.notification_email_or_default,
        subject: subject_for_failure
      )
    end

    private

    def subject_for_complete
      safe_format(s_('VirtualRegistry|Cache cleanup completed for %{group_name}'), group_name: @group.name)
    end

    def subject_for_failure
      safe_format(s_('VirtualRegistry|Cache cleanup failed for %{group_name}'), group_name: @group.name)
    end
  end
end
