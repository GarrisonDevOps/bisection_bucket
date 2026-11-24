# frozen_string_literal: true

module GitlabSubscriptions
  class PaintedDoorRequestEligibility
    include ::Gitlab::Utils::StrongMemoize

    FEATURES = {
      duo_panel: { callout: 'duo_panel_request_painted_door', check_credits: true },
      explore_premium: { callout: 'explore_premium_request_painted_door', check_credits: false }
    }.freeze

    def initialize(user:, namespace:, feature:)
      @user = user
      @namespace = namespace
      @config = FEATURES.fetch(feature)
    end

    # Runs on every signed-in page render: request-cached checks go first, DB queries last.
    def eligible?
      ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) &&
        eligible_namespace? &&
        eligible_user? &&
        credits_allow_request? &&
        root.member_of_self_or_descendant?(user)
    end
    strong_memoize_attr :eligible?

    def requested?
      user.dismissed_callout_for_group?(feature_name: callout, group: root)
    end

    def root
      namespace&.root_ancestor
    end

    private

    attr_reader :user, :namespace, :config

    def eligible_namespace?
      root.is_a?(Group) &&
        ::Feature.enabled?(:painted_door_request_ctas, root) &&
        root.free_plan?
    end

    def eligible_user?
      !user.gitlab_team_member? && !::Ability.allowed?(user, :edit_billing, root)
    end

    def credits_allow_request?
      !check_credits? || !root.has_active_gitlab_credits_add_on?
    end

    def callout
      config.fetch(:callout)
    end

    def check_credits?
      config.fetch(:check_credits)
    end
  end
end
