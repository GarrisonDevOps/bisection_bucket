# frozen_string_literal: true

module EE
  module Users
    module TermsController
      extend ActiveSupport::Concern

      prepended do
        skip_before_action :onboarding_redirect

        include GoogleAnalyticsCSP
      end
    end
  end
end
