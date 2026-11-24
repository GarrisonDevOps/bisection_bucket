# frozen_string_literal: true

module Onboarding
  module SetRedirect
    extend ActiveSupport::Concern

    private

    def verify_onboarding_enabled!
      render_404 unless ::Onboarding.enabled?
    end
  end
end
