# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module SubscriptionUsage
      class BlockedCapTypeEnum < BaseEnum
        graphql_name 'GitlabSubscriptionUsageBlockedCapType'
        description 'Type of budget cap that caused a user to be blocked'

        value 'FLAT_USER_CAP', 'Blocked by the flat per-user cap.', value: 'FLAT_USER_CAP'
        value 'USER_OVERRIDE_CAP', 'Blocked by a per-user override cap.', value: 'USER_OVERRIDE_CAP'
      end
    end
  end
end
