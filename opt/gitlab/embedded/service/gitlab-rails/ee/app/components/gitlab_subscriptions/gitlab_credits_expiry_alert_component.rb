# frozen_string_literal: true

module GitlabSubscriptions
  class GitlabCreditsExpiryAlertComponent < ViewComponent::Base
    include Gitlab::Utils::StrongMemoize

    EXPIRING_FEATURE_ID = 'gitlab_credits_expiring_alert'
    EXPIRED_FEATURE_ID = 'gitlab_credits_expired_alert'

    def initialize(user:, group:)
      @user = user
      @group = group
    end

    private

    attr_reader :user, :group

    def render?
      user.present? &&
        ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) &&
        group.root? &&
        !group.paid? &&
        add_on_purchase.present? &&
        Date.current >= alert_starts_on &&
        Ability.allowed?(user, :edit_billing, group)
    end

    def add_on_purchase
      GitlabSubscriptions::AddOnPurchase
        .for_gitlab_credits
        .non_trial
        .by_namespace(group)
        .first
    end
    strong_memoize_attr :add_on_purchase

    def expires_on
      add_on_purchase.expires_on
    end

    def alert_starts_on
      expires_on - ::SubscriptionPresenter::RENEWAL_ALLOWED_PERIOD_DAYS.days
    end

    def expired?
      Date.current >= expires_on
    end

    def feature_id
      expired? ? EXPIRED_FEATURE_ID : EXPIRING_FEATURE_ID
    end

    # Dismissals from an earlier term should not hide this term's alert.
    def ignore_dismissal_earlier_than
      (expired? ? expires_on : alert_starts_on).beginning_of_day
    end

    def title
      if expired?
        s_('UsageBilling|Your GitLab Credits subscription has expired')
      else
        format(s_('UsageBilling|Your GitLab Credits subscription expires on %{date}'),
          date: l(expires_on, format: :long))
      end
    end

    def body
      if expired?
        s_('UsageBilling|Your group no longer has monthly credits. Renew to restore them.')
      else
        s_("UsageBilling|Renew to keep your group's monthly credits after this date.")
      end
    end

    def renew_path
      ::Gitlab::Routing.url_helpers.subscription_portal_renew_subscription_by_name_url(
        add_on_purchase.purchase_xid
      )
    end
  end
end
