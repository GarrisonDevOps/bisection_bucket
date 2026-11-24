# frozen_string_literal: true

module Types
  module WebHooks
    class GroupHookType < BaseObject
      graphql_name 'GroupHook'

      authorize :read_webhook

      include Types::WebHooks::HookType

      field :id, Types::GlobalIDType[::GroupHook],
        null: false,
        description: 'ID of the webhook.'

      field :member_events, GraphQL::Types::Boolean,
        null: false,
        description: 'Whether the webhook is triggered on member events.'

      field :project_events, GraphQL::Types::Boolean,
        null: false,
        description: 'Whether the webhook is triggered on project events.'

      field :subgroup_events, GraphQL::Types::Boolean,
        null: false,
        description: 'Whether the webhook is triggered on subgroup events.'

      field :vulnerability_events, GraphQL::Types::Boolean,
        null: false,
        description: 'Whether the webhook is triggered on vulnerability events.'
    end
  end
end
