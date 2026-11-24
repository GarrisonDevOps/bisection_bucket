# frozen_string_literal: true

module Types
  module Notifications
    class TargetedMessageType < BaseObject
      graphql_name 'TargetedMessage'
      description 'Represents a targeted message'

      authorize :read_namespace

      field :id,
        GraphQL::Types::ID,
        null: false,
        description: 'ID of the targeted message.'

      field :target_type,
        GraphQL::Types::String,
        null: false,
        description: 'Type of the targeted message (e.g., banner_page_level).'

      field :roles,
        [GraphQL::Types::Int],
        null: false,
        description: 'Roles targeted by the message. Empty array means all roles.'
    end
  end
end
