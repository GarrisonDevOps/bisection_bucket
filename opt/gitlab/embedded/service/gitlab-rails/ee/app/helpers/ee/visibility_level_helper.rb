# frozen_string_literal: true

module EE
  module VisibilityLevelHelper
    include SafeFormatHelper
    extend ::Gitlab::Utils::Override

    override :group_public_visibility_billing_path
    def group_public_visibility_billing_path(group)
      return super unless saas_group_public_visibility_description?(group)

      group_billings_path(group)
    end

    private

    override :group_public_visibility_description
    def group_public_visibility_description(group)
      return super unless saas_group_public_visibility_description?(group)

      help_link = link_to('', help_page_path('user/free_user_limit.md'), target: '_blank', rel: 'noopener noreferrer')
      billing_link = link_to('', group_billings_path(group), target: '_blank', rel: 'noopener noreferrer')
      safe_format(
        s_(
          'VisibilityLevel|The group, any public projects, and any of their members, issues, ' \
            'and merge requests can be viewed without authentication. ' \
            'Public groups and projects will be indexed by search engines. ' \
            'Read more about %{help_link_start}free user limits%{help_link_end}, ' \
            'or %{billing_link_start}upgrade to a paid tier%{billing_link_end}.'
        ),
        tag_pair(help_link, :help_link_start, :help_link_end),
        tag_pair(billing_link, :billing_link_start, :billing_link_end)
      )
    end

    # sometimes this is called without a group and in that case we use the default description
    def saas_group_public_visibility_description?(group)
      group && !group.new_record? && ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
    end
  end
end
