# frozen_string_literal: true

module Types
  module Cd
    class RolloutTransitionType < ::Types::BaseObject
      graphql_name 'CdRolloutTransition'
      description 'Continuous deployment rollout transition journal entry.'

      connection_type_class Types::CountableConnectionType

      authorize :read_cd_rollout
      authorize_granular_token permissions: :read_cd_rollout,
        boundaries: [
          { boundary: :instance, boundary_type: :instance }
        ]

      field :id, Types::GlobalIDType[::Cd::RolloutTransition],
        null: false,
        description: 'Global ID of the rollout transition.'

      field :event, GraphQL::Types::String,
        null: false,
        description: 'Event that triggered the transition.'

      field :from_state, ::Types::Cd::RolloutTransitionStateEnum,
        null: false,
        description: 'State the rollout transitioned from.'

      field :to_state, ::Types::Cd::RolloutTransitionStateEnum,
        null: false,
        description: 'State the rollout transitioned to.'

      field :principal, GraphQL::Types::String,
        null: false,
        description: 'Identity reference of the principal that triggered the transition, ' \
          'for example `user:1234`.'

      field :principal_user, ::Types::UserType,
        null: true,
        description: 'User that triggered the transition, when the principal identifies ' \
          'a user that still exists; null for other principal kinds or a deleted user.',
        experiment: { milestone: '19.3' }

      field :on_behalf_of, GraphQL::Types::String,
        null: true,
        description: 'Originating principal a composite-identity action was performed on behalf of.'

      field :reason, GraphQL::Types::String,
        null: true,
        description: 'Reason for the transition.'

      field :resolution_reason, GraphQL::Types::String,
        null: true,
        description: 'Reason given when resolving an approval gate, for an approve/reject transition.'

      field :triggered_by, GraphQL::Types::String,
        null: true,
        description: 'Identifier of what triggered the transition.'

      field :created_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the transition was recorded.'

      def principal_user
        user_id = object.principal_user_id
        return unless user_id

        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::User, user_id).find
      end
    end
  end
end
