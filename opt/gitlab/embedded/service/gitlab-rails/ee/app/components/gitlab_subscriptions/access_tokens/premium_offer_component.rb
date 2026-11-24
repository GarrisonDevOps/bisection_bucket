# frozen_string_literal: true

module GitlabSubscriptions
  module AccessTokens
    class PremiumOfferComponent < ViewComponent::Base
      include ::SafeFormatHelper

      OFFERS = {
        group: {
          tracking_source: 'group-access-tokens-upgrade-card',
          upgrade_event: 'click_upgrade_to_premium_on_group_access_tokens',
          explore_event: 'click_explore_plans_on_group_access_tokens',
          learn_more_event: 'click_learn_more_on_group_access_tokens'
        },
        project: {
          tracking_source: 'project-access-tokens-upgrade-card',
          upgrade_event: 'click_upgrade_to_premium_on_project_access_tokens',
          explore_event: 'click_explore_plans_on_project_access_tokens',
          # Untracked on purpose: the docs text is a contextual link, not a CTA.
          # https://gitlab.com/gitlab-org/gitlab/-/merge_requests/251177#note_3782450693
          learn_more_event: nil
        }
      }.freeze

      def initialize(resource:)
        @resource = resource
      end

      private

      attr_reader :resource

      def group?
        resource.is_a?(::Group)
      end

      def offer
        @offer ||= OFFERS.fetch(group? ? :group : :project)
      end

      def upgrade_event
        offer[:upgrade_event]
      end

      def explore_event
        offer[:explore_event]
      end

      def heading
        if group?
          s_('AccessTokens|Try group access tokens with Premium')
        else
          s_('AccessTokens|Try project access tokens with Premium')
        end
      end

      def body_text
        link = helpers.link_to('', docs_url,
          target: '_blank', rel: 'noopener noreferrer',
          data: { event_tracking: offer[:learn_more_event] }.compact)

        safe_format(body_message, tag_pair(link, :link_start, :link_end))
      end

      def body_message
        if group?
          s_('AccessTokens|%{link_start}Group access token%{link_end} creation is not available ' \
            'on GitLab Free. Upgrade to Premium to create tokens scoped to this group and its projects.')
        else
          s_('AccessTokens|%{link_start}Project access token%{link_end} creation is not available ' \
            'on GitLab Free. Upgrade to Premium to create a token scoped to a project.')
        end
      end

      def docs_url
        if group?
          helpers.help_page_path('user/group/settings/group_access_tokens.md')
        else
          helpers.help_page_path('user/project/settings/project_access_tokens.md')
        end
      end

      def upgrade_to_premium_url
        premium_plan = plans_data&.find { |plan| plan.code == ::GitlabSubscriptions::SystemDefined::Plan::PREMIUM }

        ::GitlabSubscriptions::PurchaseUrlBuilder
          .new(plan_id: premium_plan&.id, namespace: root_ancestor)
          .build(source: offer[:tracking_source])
      end

      def explore_plans_url
        helpers.group_billings_path(root_ancestor, source: offer[:tracking_source])
      end

      def plans_data
        GitlabSubscriptions::FetchSubscriptionPlansService
          .new(plan: root_ancestor.plan_name_for_upgrading, namespace_id: root_ancestor.id)
          .execute
      end

      def root_ancestor
        @root_ancestor ||= resource.root_ancestor
      end
    end
  end
end
