# frozen_string_literal: true

module GitlabSubscriptions
  class DiscoverPremiumComponent < DiscoverDuoCoreTrialComponent
    extend ::Gitlab::Utils::Override

    override :initialize
    def initialize(license:)
      @license = license
    end

    private

    attr_reader :license

    override :trial_active?
    def trial_active?
      GitlabSubscriptions::Trials.self_managed_non_dedicated_active_ultimate_trial?(license)
    end

    override :hero_tagline_text
    def hero_tagline_text
      safe_join([
        content_tag(:h3, s_('DuoCoreTrialDiscover|Now featuring GitLab Duo Agent Platform'), class: 'gl-heading-4'),
        s_(
          'DuoCoreTrialDiscover|Enterprise-grade AI-native capabilities to help ' \
            'you move faster while maintaining security and IP protection'
        )
      ])
    end

    override :buy_now_link
    def buy_now_link
      promo_pricing_url(query: { deployment: 'self-managed' })
    end

    override :show_hand_raise_lead?
    def show_hand_raise_lead?
      false
    end
  end
end
