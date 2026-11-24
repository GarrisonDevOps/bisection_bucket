# frozen_string_literal: true

module GitlabSubscriptions
  module CodeSuggestionsHelper
    include GitlabSubscriptions::SubscriptionHelper

    def add_duo_pro_seats_url(subscription_name)
      ::Gitlab::Routing.url_helpers.subscription_portal_add_sm_duo_pro_seats_url(subscription_name)
    end
  end
end
