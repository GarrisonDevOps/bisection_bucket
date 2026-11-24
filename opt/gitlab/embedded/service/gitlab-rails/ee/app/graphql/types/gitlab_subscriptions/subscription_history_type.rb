# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    class SubscriptionHistoryType < BaseObject
      graphql_name 'GitlabSubscriptionHistory'
      description 'Describes the subscription history of a given namespace'

      authorize :read_billing

      field :created_at, Types::TimeType,
        null: true,
        description: 'Timestamp of the subscription history entry creation.'

      field :start_date, Types::TimeType,
        null: true,
        description: 'Subscription start date.'

      field :end_date, Types::TimeType,
        null: true,
        description: 'Subscription end date.'

      field :seats, GraphQL::Types::Int,
        null: true,
        description: 'Seats purchased in subscription.'

      field :seats_in_use, GraphQL::Types::Int,
        null: true,
        description: 'Seats being used in subscription.'

      field :max_seats_used, GraphQL::Types::Int,
        null: true,
        description: 'Maximum seats used in subscription.'

      field :change_type, SubscriptionHistoryChangeTypeEnum,
        null: true,
        description: 'Indicates what type of change in the subscription has happened.'
    end
  end
end
