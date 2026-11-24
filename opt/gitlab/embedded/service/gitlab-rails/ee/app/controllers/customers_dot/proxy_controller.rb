# frozen_string_literal: true

module CustomersDot
  class ProxyController < ApplicationController
    skip_before_action :authenticate_user!
    before_action :ensure_feature_available!

    feature_category :subscription_management
    urgency :low

    def graphql
      response = Gitlab::HTTP.post(subscription_portal_graphql_url,
        body: request.raw_post,
        headers: forward_headers
      )

      render json: response.body, status: response.code
    end

    private

    def ensure_feature_available!
      render_404 unless ::Gitlab::Saas.feature_available?(:cdot_graphql_proxy)
    end

    def forward_headers
      {}.tap do |headers|
        headers['Content-Type'] = 'application/json'
        headers['Authorization'] = "Bearer #{Gitlab::CustomersDot::Jwt.new(current_user).encoded}" if current_user
      end
    end
  end
end
