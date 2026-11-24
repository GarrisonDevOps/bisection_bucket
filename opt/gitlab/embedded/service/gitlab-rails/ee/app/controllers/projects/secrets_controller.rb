# frozen_string_literal: true

module Projects
  class SecretsController < Projects::ApplicationController
    include ::SecretsManagement::DismissesNavBadge

    feature_category :secrets_management
    urgency :low, [:index]

    layout 'project'

    before_action :authorize_view_secrets!

    before_action :dismiss_secrets_manager_badge, only: [:index]

    private

    def authorize_view_secrets!
      render_404 unless can?(current_user, :read_project_secrets, project)
    end
  end
end
