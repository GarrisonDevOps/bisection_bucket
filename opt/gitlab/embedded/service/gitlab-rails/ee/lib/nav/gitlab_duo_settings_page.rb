# frozen_string_literal: true

module Nav
  module GitlabDuoSettingsPage
    include ::GitlabSubscriptions::SubscriptionHelper
    include ::GitlabSubscriptions::CodeSuggestionsHelper

    def show_gitlab_duo_settings_menu_item?(group)
      group.usage_quotas_enabled? &&
        show_gitlab_duo_settings_app?(group)
    end

    def gitlab_duo_subscription_valid?(group)
      # Guard this feature for EE users only https://docs.gitlab.com/ee/development/ee_features.html#guard-your-ee-feature
      # This is to prevent it showing up in CE and free EE
      License.feature_available?(:code_suggestions) &&
        (
          !group.has_free_or_no_subscription? ||
          # group has Duo Pro add-on trial on a Free tier
          GitlabSubscriptions::Trials::DuoPro.show_duo_usage_settings?(group) ||
          # group has an active gitlab_credits add-on (SaaS free tier with credits)
          group.root_ancestor.has_active_gitlab_credits_add_on?
        )
    end

    def show_gitlab_duo_settings_app?(group)
      gitlab_com_subscription? && gitlab_duo_subscription_valid?(group)
    end
  end
end
