# frozen_string_literal: true

module GitlabSubscriptions
  module AddOns
    VARIANTS = {
      code_suggestions: {
        email: 'duo_pro_email',
        product_interaction: 'duo_pro_add_on_seat_assigned'
      },
      duo_enterprise: {
        email: 'duo_enterprise_email',
        product_interaction: 'duo_enterprise_add_on_seat_assigned'
      }
    }.freeze
  end
end
