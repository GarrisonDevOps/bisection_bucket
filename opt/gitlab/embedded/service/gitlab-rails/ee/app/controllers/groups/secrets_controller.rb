# frozen_string_literal: true

module Groups
  class SecretsController < Groups::ApplicationController
    include ::SecretsManagement::DismissesNavBadge

    feature_category :secrets_management
    urgency :low, [:index]

    layout 'group'

    before_action :authorize_view_secrets!

    before_action :dismiss_secrets_manager_badge, only: [:index]

    private

    def authorize_view_secrets!
      render_404 unless can?(current_user, :read_secret, group)
    end
  end
end
