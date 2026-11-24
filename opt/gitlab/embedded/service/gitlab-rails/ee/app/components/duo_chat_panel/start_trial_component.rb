# frozen_string_literal: true

module DuoChatPanel
  class StartTrialComponent < ViewComponent::Base
    include DuoChatPanel::LegacyCallout
    include DuoChatPanel::StartTrial

    DEFAULT_TRIAL_DURATION = 30

    def initialize(container:, user:)
      @container = container
      @user = user
    end

    private

    attr_reader :container, :user

    def data
      path = trial_path(@user, source: @container.record)

      trial_duration =
        if path.nil?
          nil
        elsif ::Gitlab::Saas.feature_available?(:subscriptions_trials)
          GitlabSubscriptions::TrialDurationService.new.execute
        else
          DEFAULT_TRIAL_DURATION
        end

      {
        testid: 'duo-chat-panel-start-trial',
        new_trial_path: path,
        trial_duration: trial_duration,
        can_start_trial: path.present?.to_s,
        auto_expand: auto_expanded?(user).to_s,
        buy_credits_path: buy_credits_path
      }.compact
    end

    def buy_credits_path
      return unless saas?

      root = container.root_ancestor
      return unless root.is_a?(::Group) && Ability.allowed?(user, :edit_billing, root)

      ::Gitlab::Routing.url_helpers.subscription_portal_gitlab_com_purchase_credits_url(root.id)
    end
  end
end
