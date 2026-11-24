# frozen_string_literal: true

module GitlabSubscriptions
  class UpgradePresenter < Gitlab::View::Presenter::Simple
    def initialize(user, namespace: nil, project: nil)
      @mediator = build_mediator(user, namespace, project)
    end

    delegate :attributes, to: :mediator

    private

    attr_reader :mediator

    def build_mediator(user, namespace, project)
      unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        return SelfManagedMediator.new(user, ::License.current)
      end

      return PersonalProjectMediator.new(user, namespace, project) if project&.saved? && project.personal?

      if namespace.present?
        NamespaceMediator.new(user, namespace)
      else
        GlobalMediator.new(user)
      end
    end

    class SelfManagedMediator
      def initialize(user, license)
        @user = user
        @license = license
      end

      def attributes
        return {} unless eligible_for_upgrade?

        {
          upgrade_link: {
            url: ::Gitlab::Routing.url_helpers.promo_pricing_url(query: { deployment: 'self-managed' }),
            text: s_('CurrentUser|Upgrade subscription')
          }
        }
      end

      private

      attr_reader :user, :license

      def eligible_for_upgrade?
        GitlabSubscriptions::Trials.self_managed_non_dedicated_active_ultimate_trial?(license) &&
          Ability.allowed?(user, :admin_all_resources)
      end
    end

    class PersonalProjectMediator
      def initialize(user, namespace, project)
        @user = user
        @namespace = namespace
        @project = project
      end

      def attributes
        return {} unless Ability.allowed?(@user, :change_namespace, @project)

        {
          upgrade_link: {
            url: ::Gitlab::Routing.url_helpers.project_transfer_personal_path(@project),
            text: s_('CurrentUser|Upgrade subscription'),
            is_personal_project: true,
            project_name: @project.name,
            project_full_path: @project.full_path
          }
        }
      end
    end

    class NamespaceMediator
      def initialize(user, namespace)
        @user = user
        @namespace = namespace
      end

      def attributes
        return {} unless eligible_for_upgrade?

        {
          upgrade_link: {
            url: ::Gitlab::Routing.url_helpers.group_billings_path(namespace),
            text: s_('CurrentUser|Upgrade subscription')
          }
        }
      end

      private

      attr_reader :user, :namespace

      def eligible_for_upgrade?
        return false unless namespace.persisted?
        return false if namespace.self_deletion_scheduled?

        (!namespace.paid? || namespace.trial?) && Ability.allowed?(user, :edit_billing, namespace)
      end
    end

    class GlobalMediator
      include Gitlab::Utils::StrongMemoize

      def initialize(user)
        @user = user
      end

      def attributes
        link = upgrade_link
        return {} if link.empty?

        { upgrade_link: link }
      end

      private

      attr_reader :user

      def upgrade_link
        if can_upgrade_subscription?
          {
            url: owned_groups_url,
            text: s_('CurrentUser|Upgrade subscription')
          }
        elsif can_start_trial?
          {
            url: ::Gitlab::Routing.url_helpers.new_trial_path(
              glm_source: 'gitlab.com', glm_content: 'top-right-dropdown'
            ),
            text: s_('CurrentUser|Start an Ultimate trial')
          }
        else
          {}
        end
      end

      def can_upgrade_subscription?
        owned_groups_url.present?
      end

      def owned_groups_url
        cache_key = ['users', user.id, 'owned_groups_url']
        Rails.cache.fetch(cache_key, expires_in: 10.minutes) do
          groups = user.owned_free_or_trial_groups_with_limit(2)

          next if groups.empty?

          if groups.one?
            ::Gitlab::Routing.url_helpers.group_billings_path(groups.first)
          else
            ::Gitlab::Routing.url_helpers.profile_billings_path
          end
        end
      end
      strong_memoize_attr :owned_groups_url

      def can_start_trial?
        Rails.cache.fetch(['users', user.id, 'can_start_trial'], expires_in: 10.minutes) do
          !owns_ultimate_tier_namespace? &&
            GitlabSubscriptions::Trials.no_eligible_namespaces_for_user?(user, fail_fast: true)
        end
      end

      # Community program plans (OSS/EDU/non-profit) grant Ultimate features but are not
      # trial-eligible, so without this their owners fall through to the trial branch.
      def owns_ultimate_tier_namespace?
        user.owns_paid_namespace?(plans: ::GitlabSubscriptions::SystemDefined::Plan::ULTIMATE_TIER_PLANS)
      end
    end
  end
end
