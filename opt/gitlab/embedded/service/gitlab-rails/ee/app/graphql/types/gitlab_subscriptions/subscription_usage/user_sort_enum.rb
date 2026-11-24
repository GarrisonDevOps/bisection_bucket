# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module SubscriptionUsage
      class UserSortEnum < BaseEnum
        graphql_name 'GitlabSubscriptionUsageUserSort'
        description 'Values for sorting users in subscription usage'

        value 'NAME_ASC', 'Name by ascending order.', value: :name_asc
        value 'NAME_DESC', 'Name by descending order.', value: :name_desc
        value 'TOTAL_CREDITS_USED_ASC', 'Total credits used by ascending order.', value: :total_credits_used_asc
        value 'TOTAL_CREDITS_USED_DESC', 'Total credits used by descending order.', value: :total_credits_used_desc
      end
    end
  end
end
