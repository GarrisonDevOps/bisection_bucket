# frozen_string_literal: true

module Onboarding
  module InProgress
    extend ActiveSupport::Concern

    private

    def verify_in_onboarding_flow!
      redirect_to root_path unless ::Onboarding.user_onboarding_in_progress?(current_user)
    end
  end
end
