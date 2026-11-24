# frozen_string_literal: true

module Organizations
  class AccessController < ApplicationController
    feature_category :organization
    urgency :low

    before_action :authorize_read_organization_user!
    before_action :check_feature_enabled

    def index; end

    def artifact_registry; end

    private

    def check_feature_enabled
      render_404 unless Feature.enabled?(:organization_access_ui, current_user)
    end
  end
end
