# frozen_string_literal: true

module Namespaces
  module FreeUserCapHelper
    def over_limit_body_text(namespace_name)
      safe_format(
        s_(
          'FreeUserCap|You have exceeded your limit of %{free_user_limit} users for %{namespace_name} group ' \
          'because users were added to a group inherited by a group or project in the ' \
          '%{namespace_name} group.'
        ),
        namespace_name: namespace_name, free_user_limit: Namespaces::FreeUserCap.dashboard_limit
      )
    end

    def over_limit_body_secondary_text(start_trial_url, upgrade_url, trial_duration, html_tags: true)
      result = safe_format(
        s_(
          'FreeUserCap|To remove the %{link_start}read-only%{link_end} state and regain write access, ' \
          'you can reduce the number of users in your top-level group to %{free_user_limit} users or less. ' \
          'You can also %{upgrade_start}upgrade%{upgrade_end} to a paid tier, which do not have user limits. ' \
          'If you need additional time, you can %{trial_start}start a free %{duration}-day trial%{trial_end} which ' \
          'includes unlimited users.'
        ),
        tag_pair(
          link_to('', ::Gitlab::Routing.url_helpers.help_page_path('user/free_user_limit.md')), :link_start, :link_end
        ),
        tag_pair(link_to('', start_trial_url), :trial_start, :trial_end),
        tag_pair(link_to('', upgrade_url), :upgrade_start, :upgrade_end),
        free_user_limit: Namespaces::FreeUserCap.dashboard_limit,
        duration: trial_duration
      )

      return result if html_tags

      strip_tags(result)
    end

    def over_limit_title
      s_("FreeUserCap|You've exceeded your user limit")
    end
  end
end
