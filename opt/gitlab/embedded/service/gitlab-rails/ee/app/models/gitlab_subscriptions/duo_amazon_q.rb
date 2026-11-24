# frozen_string_literal: true

module GitlabSubscriptions
  module DuoAmazonQ
    def self.any_add_on_purchase
      GitlabSubscriptions::AddOnPurchase.for_self_managed.for_duo_amazon_q.first
    end
  end
end
