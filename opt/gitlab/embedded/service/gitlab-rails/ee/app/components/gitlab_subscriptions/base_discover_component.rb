# frozen_string_literal: true

module GitlabSubscriptions
  class BaseDiscoverComponent < ViewComponent::Base
    # @param [Namespace or Group] namespace

    def initialize(namespace:)
      @namespace = namespace
    end

    private

    attr_reader :namespace

    delegate :page_title, to: :helpers

    def trial_type
      raise Gitlab::AbstractMethodError
    end

    def trial_active?
      raise Gitlab::AbstractMethodError
    end

    def text_page_title
      raise Gitlab::AbstractMethodError
    end

    def hero_logo
      raise Gitlab::AbstractMethodError
    end

    def hero_logo_dark
      raise Gitlab::AbstractMethodError
    end

    def hero_header_text
      raise Gitlab::AbstractMethodError
    end

    def hero_tagline_text
      nil
    end

    def buy_now_link
      raise Gitlab::AbstractMethodError
    end

    def cta_button_text
      raise Gitlab::AbstractMethodError
    end

    def hero_video
      raise Gitlab::AbstractMethodError
    end

    def why_section_header_text
      raise Gitlab::AbstractMethodError
    end

    def core_feature_one_header_text
      raise Gitlab::AbstractMethodError
    end

    def hero_thumbnail
      raise Gitlab::AbstractMethodError
    end

    def discover_card_collection
      raise Gitlab::AbstractMethodError
    end

    def core_section_one_card_collection
      raise Gitlab::AbstractMethodError
    end

    def show_hand_raise_lead?
      true
    end

    def hand_raise_lead_data
      {
        namespace_id: namespace.id,
        glm_content: glm_content,
        cta_tracking: {
          action: 'click_contact_sales',
          label: trial_status_cta_label
        }.to_json,
        button_attributes: {
          category: buy_now_link ? 'secondary' : 'primary',
          variant: 'confirm',
          class: 'gl-w-full @sm/panel:gl-w-auto',
          'data-testid': 'trial-discover-hand-raise-lead-button'
        }.to_json
      }
    end

    def glm_content
      raise Gitlab::AbstractMethodError
    end

    def trial_status_cta_label
      if trial_active?
        "#{trial_type}_active_trial"
      else
        "#{trial_type}_expired_trial"
      end
    end
  end
end
