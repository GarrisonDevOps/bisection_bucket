# frozen_string_literal: true

module Onboarding
  class AutomaticTrialRegistration < TrialRegistration
    extend ::Gitlab::Utils::Override

    # string methods

    override :product_interaction
    def self.product_interaction
      'SaaS Trial - defaulted'
    end
  end
end
