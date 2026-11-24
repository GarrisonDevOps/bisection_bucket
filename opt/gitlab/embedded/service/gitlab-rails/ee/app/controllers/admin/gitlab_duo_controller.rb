# frozen_string_literal: true

# EE:Self Managed
module Admin
  class GitlabDuoController < Admin::ApplicationController
    include ::GitlabSubscriptions::CodeSuggestionsHelper

    respond_to :html

    feature_category :ai_abstraction_layer
    urgency :low

    before_action :ensure_feature_available!

    def show; end

    private

    def ensure_feature_available!
      render_404 unless self_managed_duo_available?
    end

    def self_managed_duo_available?
      return false if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

      License.current&.paid? || GitlabSubscriptions::Duo.active_self_managed_gitlab_credits?
    end
  end
end
