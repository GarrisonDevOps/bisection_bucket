# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module SubscriptionUsage
      class DailyUsageSortEnum < BaseEnum
        graphql_name 'DailyUsageSort'
        description 'Values for sorting daily usage entries'

        value 'DATE_ASC', 'Date by ascending order.', value: :date_asc
        value 'DATE_DESC', 'Date by descending order.', value: :date_desc
        value 'CREDITS_USED_ASC', 'Credits used by ascending order.', value: :credits_used_asc
        value 'CREDITS_USED_DESC', 'Credits used by descending order.', value: :credits_used_desc
      end
    end
  end
end
