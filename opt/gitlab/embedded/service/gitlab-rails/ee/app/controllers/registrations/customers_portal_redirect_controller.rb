# frozen_string_literal: true

module Registrations
  class CustomersPortalRedirectController < ApplicationController
    include OneTrustCSP
    include GoogleAnalyticsCSP
    include GoogleSyndicationCSP
    include ::Gitlab::Utils::StrongMemoize

    layout 'minimal'

    RETURN_TO_SESSION_KEY = :customers_portal_return_to

    before_action :verify_unification_enabled!

    feature_category :onboarding

    def show
      @customers_portal_url = ::Gitlab::Utils.add_url_parameters(user_return_to, auto_submit_sso: 'true')
    end

    private

    def verify_unification_enabled!
      render_404 unless onboarding_status_presenter.unification_enabled?
    end

    def onboarding_status_presenter
      Onboarding::StatusPresenter.new({}, nil, current_user)
    end
    strong_memoize_attr :onboarding_status_presenter

    def user_return_to
      session[RETURN_TO_SESSION_KEY].presence || stored_location_for(:user)&.tap do |loc|
        session[RETURN_TO_SESSION_KEY] = loc
      end
    end
    strong_memoize_attr :user_return_to
  end
end
