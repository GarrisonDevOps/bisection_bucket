# frozen_string_literal: true

module GitlabSubscriptions
  module HandRaiseLeadsHelper
    def hand_raise_modal_dataset(root_namespace)
      {
        user: {
          namespace_id: root_namespace.id,
          user_name: current_user.username,
          first_name: current_user.first_name,
          last_name: current_user.last_name,
          company_name: current_user.company
        }.to_json,
        submit_path: gitlab_subscriptions_hand_raise_leads_path
      }
    end

    def billing_action_hand_raise_lead_data(plan_code)
      {
        glm_content: 'billing-group',
        cta_tracking: {
          action: 'click_link',
          property: plan_code
        }.to_json,
        button_attributes: {}.to_json
      }
    end

    def code_suggestions_usage_app_hand_raise_lead_data
      {
        glm_content: 'code-suggestions',
        product_interaction: 'Requested Contact-Duo Pro Add-On',
        button_attributes: {
          'data-testid': 'code-suggestions-hand-raise-lead-button',
          category: 'secondary',
          variant: 'confirm',
          class: '@sm/panel:gl-w-auto gl-w-full @sm/panel:gl-ml-3 @sm/panel:gl-mt-0 gl-mt-3'
        }.to_json,
        cta_tracking: {
          action: 'click_button',
          label: 'code_suggestions_hand_raise_lead_form'
        }.to_json
      }
    end

    def promotion_hand_raise_lead_data(location)
      location = location.to_s

      {
        glm_content: location,
        button_text: s_('Promotions|Talk to sales'),
        button_attributes: { variant: 'confirm' }.to_json,
        cta_tracking: { action: 'click_button', label: 'promotion_talk_to_sales', property: location }.to_json
      }
    end

    def group_trial_status(group)
      strong_memoize_with(:group_trial_status, group) do
        group.trial_active? ? 'trial_active' : 'trial_expired'
      end
    end
  end
end
