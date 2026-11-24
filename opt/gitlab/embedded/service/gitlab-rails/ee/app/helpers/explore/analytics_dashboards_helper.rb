# frozen_string_literal: true

module Explore
  module AnalyticsDashboardsHelper
    # The admin GitLab Credits dashboard is self-managed only, so SaaS gets no link.
    def explore_gitlab_credits_dashboard_path
      return unless current_user&.can_admin_all_resources?
      return if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
      return unless ::License.gitlab_credits_entitled?

      admin_gitlab_credits_dashboard_index_path
    end
  end
end
