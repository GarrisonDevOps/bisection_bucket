# frozen_string_literal: true

module Admin
  module Ai
    class TermsAndConditionsController < Admin::ApplicationController
      include ::GitlabSubscriptions::CodeSuggestionsHelper

      feature_category :"self-hosted_models"
      urgency :low

      before_action :ensure_feature_enabled!

      def toggle_beta_models
        testing_terms_acceptance = ::Ai::TestingTermsAcceptance.find_by_user_id(current_user.id)

        if testing_terms_acceptance
          ::Ai::SelfHostedModels::TestingTermsAcceptance::DestroyService.new(testing_terms_acceptance).execute
        else
          ::Ai::SelfHostedModels::TestingTermsAcceptance::CreateService.new(current_user).execute
        end
      end

      private

      def ensure_feature_enabled!
        render_404 unless Ability.allowed?(current_user, :manage_self_hosted_models_settings)
      end
    end
  end
end
