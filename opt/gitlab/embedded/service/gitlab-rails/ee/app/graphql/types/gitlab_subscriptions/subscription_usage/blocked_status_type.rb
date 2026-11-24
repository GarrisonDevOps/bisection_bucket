# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module SubscriptionUsage
      class BlockedStatusType < BaseObject
        graphql_name 'GitlabSubscriptionUsageBlockedStatus'
        description 'Describes the blocked status of a user under the subscription budget cap'

        authorize_granular_token parent_authorizes: :read_user

        authorize :read_user

        field :blocked, GraphQL::Types::Boolean,
          null: false,
          description: 'Whether the user is blocked from using credits due to reaching their cap.'

        field :cap_type, BlockedCapTypeEnum,
          null: true,
          description: 'Type of cap that caused the block. Null when not blocked.'
      end
    end
  end
end
