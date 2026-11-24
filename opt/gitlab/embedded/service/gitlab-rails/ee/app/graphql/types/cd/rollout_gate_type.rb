# frozen_string_literal: true

module Types
  module Cd
    class RolloutGateType < ::Types::BaseObject
      graphql_name 'CdRolloutGate'
      description 'Continuous deployment rollout approval gate, derived from its transition journal.'

      connection_type_class Types::CountableConnectionType

      authorize :read_cd_rollout
      authorize_granular_token permissions: :read_cd_rollout,
        boundaries: [
          { boundary: :instance, boundary_type: :instance }
        ]

      field :id, Types::GlobalIDType[::Cd::RolloutTransition],
        null: false,
        description: 'Global ID of the transition that opened the gate.'

      field :state, ::Types::Cd::RolloutGateStateEnum,
        null: false,
        description: 'State of the gate.'

      field :name, GraphQL::Types::String,
        null: true,
        description: 'Label of the gate, derived from the step it was opened for.'

      field :reason, GraphQL::Types::String,
        null: true,
        description: 'Reason the approval was requested for.'

      field :resolution_reason, GraphQL::Types::String,
        null: true,
        description: 'Reason given when the gate was resolved, if any.'

      # rubocop:disable GraphQL/ExtractType -- resolvedAt/resolvedBy are the gate's own resolution
      # details, not a logical sub-grouping worth its own type
      field :resolved_at, Types::TimeType,
        null: true,
        description: 'Timestamp of when the gate was resolved, null while still pending.'

      field :resolved_by, Types::UserType,
        null: true,
        description: 'User that resolved the gate, when the resolving principal identifies ' \
          'a user that still exists; null while pending or for other principal kinds.'
      # rubocop:enable GraphQL/ExtractType

      field :step, ::Types::Cd::RolloutStepType,
        null: true,
        description: 'Rollout step the gate was opened for, null for a gate opened for a non-step reason.'

      def id
        object.request_transition.to_global_id
      end

      def resolved_by
        user_id = object.resolved_by_user_id
        return unless user_id

        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::User, user_id).find
      end
    end
  end
end
