# frozen_string_literal: true

module Namespaces
  module FreeUserCap
    class UsageQuotaTrialAlertComponent < BaseAlertComponent
      private

      include SafeFormatHelper

      USAGE_QUOTA_TRIAL_ALERT = 'usage_quota_trial_alert'

      def breached_cap_limit?
        namespace.trial_active? &&
          ::Namespaces::FreeUserCap::Enforcement.new(namespace).qualified_namespace?
      end

      def variant
        :info
      end

      def base_alert_data
        {
          testid: 'usage-quota-trial-alert'
        }
      end

      def close_button_data
        { testid: 'usage-quota-trial-dismiss' }
      end

      def feature_name
        USAGE_QUOTA_TRIAL_ALERT
      end

      def alert_attributes
        {
          title: n_(
            'On %{end_date}, your trial will end and %{namespace_name} will be limited to ' \
            '%{free_user_limit} user',
            'On %{end_date}, your trial will end and %{namespace_name} will be limited to ' \
            '%{free_user_limit} users',
            free_user_limit
          ) % {
            end_date: l(namespace.trial_ends_on, format: :long),
            namespace_name: namespace.name,
            free_user_limit: free_user_limit
          },
          body: safe_format(
            _("When your trial ends, you'll move to the Free tier. Free top-level namespaces with " \
              'private visibility can have only %{free_user_limit} users. If your namespace ' \
              'exceeds this limit, it will become ' \
              '%{read_only_start}read-only%{read_only_end}. To prevent this, ' \
              '%{upgrade_start}upgrade to a paid tier%{upgrade_end}.'),
            tag_pair(read_only_namespaces_link, :read_only_start, :read_only_end),
            tag_pair(upgrade_link, :upgrade_start, :upgrade_end),
            free_user_limit: free_user_limit
          )
        }
      end

      def read_only_namespaces_link
        link_to('', help_page_path('user/read_only_namespaces.md', anchor: 'read-only-namespaces'),
          target: '_blank', rel: 'noopener noreferrer')
      end

      def upgrade_link
        link_to('', group_billings_path(namespace))
      end
    end
  end
end
