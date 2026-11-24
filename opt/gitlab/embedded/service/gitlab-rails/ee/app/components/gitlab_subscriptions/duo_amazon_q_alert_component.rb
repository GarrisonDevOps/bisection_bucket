# frozen_string_literal: true

module GitlabSubscriptions
  class DuoAmazonQAlertComponent < ViewComponent::Base
    include Gitlab::Utils::StrongMemoize

    def initialize(user:)
      @user = user
    end

    private

    attr_reader :user

    def render?
      self_managed_instance? && add_on_purchase.present?
    end

    def self_managed_instance?
      !Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
    end

    def add_on_purchase
      GitlabSubscriptions::DuoAmazonQ.any_add_on_purchase
    end
    strong_memoize_attr :add_on_purchase

    def variant
      case days_to_expiration
      when 16..Float::INFINITY
        :info
      when 2..15
        :warning
      else
        :danger
      end
    end

    def message
      if add_on_purchase.active?
        formatted_date = l(add_on_purchase.expires_on, format: :long)
        Kernel.format(
          s_('AmazonQ|GitLab Duo with Amazon Q - Subscription ends on %{formatted_date}'),
          formatted_date: formatted_date
        )
      else
        s_('AmazonQ|Your GitLab Duo with Amazon Q subscription has ended')
      end
    end

    def days_to_expiration
      (add_on_purchase.expires_on.to_date - Date.current).to_i
    end
  end
end
