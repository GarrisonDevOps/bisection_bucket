# frozen_string_literal: true

module Types
  module Cd
    class DeploymentTransitionType < ::Types::BaseObject
      graphql_name 'CdDeploymentTransition'
      description 'Continuous deployment deployment transition journal entry.'

      connection_type_class Types::CountableConnectionType

      authorize :read_cd_rollout
      authorize_granular_token permissions: :read_cd_rollout,
        boundaries: [
          { boundary: :instance, boundary_type: :instance }
        ]

      field :id, Types::GlobalIDType[::Cd::DeploymentTransition],
        null: false,
        description: 'Global ID of the deployment transition.'

      field :event, GraphQL::Types::String,
        null: false,
        description: 'Event that triggered the transition.'

      field :from_state, ::Types::Cd::DeploymentTransitionStateEnum,
        null: false,
        description: 'State the deployment transitioned from.'

      field :to_state, ::Types::Cd::DeploymentTransitionStateEnum,
        null: false,
        description: 'State the deployment transitioned to.'

      field :principal, GraphQL::Types::String,
        null: false,
        description: 'Identity reference of the principal that triggered the transition, ' \
          'for example `user:1234`.'

      field :on_behalf_of, GraphQL::Types::String,
        null: true,
        description: 'Originating principal a composite-identity action was performed on behalf of.'

      field :reason, GraphQL::Types::String,
        null: true,
        description: 'Reason for the transition.'

      field :triggered_by, GraphQL::Types::String,
        null: true,
        description: 'Identifier of what triggered the transition.'

      field :created_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the transition was recorded.'
    end
  end
end
