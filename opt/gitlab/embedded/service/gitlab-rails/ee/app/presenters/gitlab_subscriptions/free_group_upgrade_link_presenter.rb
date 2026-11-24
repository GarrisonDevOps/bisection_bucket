# frozen_string_literal: true

module GitlabSubscriptions
  class FreeGroupUpgradeLinkPresenter < Gitlab::View::Presenter::Simple
    def initialize(user, group: nil)
      @mediator = build_mediator(user, group)
    end

    delegate :attributes, to: :mediator

    private

    attr_reader :mediator

    def build_mediator(user, group)
      if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        SaasMediator.new(user, group)
      else
        SelfManagedMediator.new(user)
      end
    end

    class SaasMediator
      def initialize(user, group)
        @mediator = group.present? ? GroupMediator.new(user, group) : GlobalMediator.new(user)
      end

      def attributes
        @mediator.attributes
      end
    end

    class GroupMediator
      def initialize(user, group)
        @user = user
        @group = group
      end

      def attributes
        upgrade_link
      end

      private

      attr_reader :user, :group

      def upgrade_link
        return {} unless eligible_for_upgrade?

        { free_group_upgrade_link: ::Gitlab::Routing.url_helpers.group_billings_path(group) }
      end

      def eligible_for_upgrade?
        return false unless group.persisted?
        return false if group.self_deletion_scheduled?

        Ability.allowed?(user, :edit_billing, group) && group.has_free_or_no_subscription?
      end
    end

    class GlobalMediator
      include Gitlab::Utils::StrongMemoize

      def initialize(user)
        @user = user
      end

      def attributes
        upgrade_link
      end

      private

      attr_reader :user

      def upgrade_link
        GitlabSubscriptions::FreeGroupUpgradeLinkCache.get(user.id) do
          compute_upgrade_link
        end
      end

      def compute_upgrade_link
        plan_name = ::GitlabSubscriptions::SystemDefined::Plan.free.name

        return {} if GitlabSubscriptions.user_has_non_free_groups?(user)

        free_owned_groups = user.owned_groups.in_specific_plans(plan_name).not_aimed_for_deletion.limit(2)

        return {} if free_owned_groups.empty?

        free_group_upgrade_links = free_owned_groups.filter_map do |group|
          GroupMediator.new(user, group).attributes[:free_group_upgrade_link]
        end

        if free_group_upgrade_links.one?
          { free_group_upgrade_link: free_group_upgrade_links.first }
        else
          { free_group_upgrade_link: ::Gitlab::Routing.url_helpers.profile_billings_path }
        end
      end
    end

    class SelfManagedMediator
      def initialize(user)
        @user = user
      end

      def attributes
        upgrade_link
      end

      private

      attr_reader :user

      def upgrade_link
        return {} unless eligible_for_upgrade?

        url = ::Gitlab::Routing.url_helpers.promo_pricing_url(
          query: { deployment: 'self-managed' }
        )
        { free_group_upgrade_link: url }
      end

      def eligible_for_upgrade?
        return false unless user.can_admin_all_resources?

        license = License.current
        return true if license.nil?
        return true if license.expired? && license.trial?
        return true if license.expired? && license.paid?

        false
      end
    end
  end
end
