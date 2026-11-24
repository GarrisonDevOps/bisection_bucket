# frozen_string_literal: true

module Admin
  class DiscoverPremiumController < Admin::ApplicationController
    include Gitlab::Utils::StrongMemoize

    before_action :verify_discover_available!

    feature_category :activation
    urgency :low

    def show
      render GitlabSubscriptions::DiscoverPremiumComponent.new(license: license)
    end

    private

    def license
      ::License.current
    end
    strong_memoize_attr :license

    def verify_discover_available!
      render_404 if ::Gitlab::Saas.feature_available?(:subscriptions_trials) || license.blank?
    end
  end
end
