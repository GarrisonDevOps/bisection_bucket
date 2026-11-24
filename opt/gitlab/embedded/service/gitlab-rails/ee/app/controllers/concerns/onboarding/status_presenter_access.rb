# frozen_string_literal: true

module Onboarding
  module StatusPresenterAccess
    extend ActiveSupport::Concern
    include ::Gitlab::Utils::StrongMemoize

    included do
      helper_method :onboarding_status_presenter
    end

    private

    def onboarding_status_presenter
      ::Onboarding::StatusPresenter.new(
        onboarding_status_presenter_params,
        onboarding_status_presenter_user_return_to,
        onboarding_status_presenter_user
      )
    end
    strong_memoize_attr :onboarding_status_presenter

    def onboarding_status_presenter_params
      {}
    end

    def onboarding_status_presenter_user_return_to
      nil
    end

    def onboarding_status_presenter_user
      current_user
    end
  end
end
