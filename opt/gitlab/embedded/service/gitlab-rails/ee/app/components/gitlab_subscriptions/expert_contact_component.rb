# frozen_string_literal: true

module GitlabSubscriptions
  class ExpertContactComponent < ViewComponent::Base
    private

    def hand_raise_lead_data
      {
        glm_content: 'billing-group',
        button_text: s_("BillingPlans|Talk to an expert"),
        button_attributes: {
          category: 'secondary',
          class: 'gl-align-text-bottom',
          'data-testid': 'expert-contact-hand-raise-lead-button'
        }.to_json,
        cta_tracking: { action: 'click_button' }.to_json
      }
    end
  end
end
