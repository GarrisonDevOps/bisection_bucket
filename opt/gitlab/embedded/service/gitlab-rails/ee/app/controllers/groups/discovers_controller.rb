# frozen_string_literal: true

module Groups
  class DiscoversController < Groups::ApplicationController
    before_action :authorize_admin_group!
    before_action :authorize_discover_page

    feature_category :activation
    urgency :low

    def show
      render GitlabSubscriptions::DiscoverComponent.new(namespace: @group)
    end

    private

    def authorize_discover_page
      render_404 unless ::Gitlab::Saas.feature_available?(:subscriptions_trials)
    end
  end
end
