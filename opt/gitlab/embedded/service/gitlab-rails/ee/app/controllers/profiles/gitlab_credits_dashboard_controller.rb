# frozen_string_literal: true

module Profiles
  class GitlabCreditsDashboardController < Profiles::ApplicationController
    before_action :ensure_feature_available!

    feature_category :consumables_cost_management
    urgency :low

    def index
      @hide_search_settings = true
      groups = current_user.groups_with_gitlab_credits.to_a

      return render_404 if groups.empty?

      @groups_with_gitlab_credits = groups.map { |group| { name: group.name, path: group.full_path } }
    end

    private

    def ensure_feature_available!
      return render_404 unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

      render_404 unless current_user.human?
    end
  end
end
