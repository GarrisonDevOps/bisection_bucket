# frozen_string_literal: true

module EE
  module UserPolicy
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    prepended do
      condition(:updating_name_disabled_for_users, scope: :global) do
        ::License.feature_available?(:disable_name_update_for_users) &&
          ::Gitlab::CurrentSettings.current_application_settings.updating_name_disabled_for_users
      end

      condition(:can_remove_self, scope: :subject) do
        @subject.can_remove_self?
      end

      desc "Personal access tokens are disabled"
      condition(:personal_access_tokens_disabled, scope: :global, score: 0) do
        ::Gitlab::CurrentSettings.personal_access_tokens_disabled?
      end

      desc "Personal access tokens are disabled by enterprise group"
      condition(:personal_access_tokens_disabled_by_enterprise_group, scope: :subject) do
        @subject.enterprise_user? && @subject.enterprise_group.disable_personal_access_tokens?
      end

      desc "User can delete the given enterprise user"
      condition(:can_delete_enterprise_user) do
        @subject.enterprise_user? && @subject.managed_by_group?(@subject.enterprise_group) &&
          can?(:delete_enterprise_user, @subject.enterprise_group)
      end

      condition(:profiles_can_be_made_private, scope: :global) { profiles_can_be_made_private? }

      rule { can?(:update_user) }.enable :update_name

      rule { updating_name_disabled_for_users & ~admin }.prevent :update_name

      rule { user_is_self & ~can_remove_self }.prevent :destroy_user

      rule { personal_access_tokens_disabled | personal_access_tokens_disabled_by_enterprise_group }
        .prevent :create_personal_access_token

      rule { ~profiles_can_be_made_private & ~admin }.prevent :make_profile_private

      rule { can_delete_enterprise_user }.enable :destroy_user
    end

    def profiles_can_be_made_private?
      return true unless ::License.feature_available?(:disable_private_profiles)

      ::Gitlab::CurrentSettings.make_profile_private
    end

    override :private_profile?
    def private_profile?
      profiles_can_be_made_private? && super
    end
  end
end
