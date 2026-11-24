# frozen_string_literal: true

# Default marketing right-panel images and heading shared across registration
# types. Each registration type can override these per step (sign-up,
# identity verification); `FreeRegistration` does so to render its own
# illustrations in place of the defaults.
module Onboarding
  module RegistrationPanelDefaults
    # nil defers to the fallback in _registration_right_panel.html.haml;
    # FreeRegistration overrides both with its own image and heading.
    def signup_page_image
      nil
    end

    def signup_page_heading
      nil
    end

    def identity_verification_panel_image
      'subscription/pipeline'
    end

    def identity_verification_panel_heading
      s_('InProductMarketing|Ship software faster')
    end
  end
end
