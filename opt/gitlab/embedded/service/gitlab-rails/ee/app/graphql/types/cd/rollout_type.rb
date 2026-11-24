# frozen_string_literal: true

module Types
  module Cd
    class RolloutType < ::Types::BaseObject
      graphql_name 'CdRollout'
      description 'Continuous deployment rollout.'

      connection_type_class Types::CountableConnectionType

      authorize :read_cd_rollout
      authorize_granular_token permissions: :read_cd_rollout,
        boundaries: [
          { boundary: :instance, boundary_type: :instance }
        ]

      field :id, Types::GlobalIDType[::Cd::Rollout],
        null: false,
        description: 'Global ID of the rollout.'

      field :iid, GraphQL::Types::Int,
        null: false,
        description: 'Internal ID of the rollout, unique and user-facing within its application.'

      field :state, ::Types::Cd::RolloutStateEnum,
        null: false,
        description: 'State of the rollout.'

      field :workflow_ref, GraphQL::Types::String,
        null: true,
        description: 'Workflow reference of the rollout.'

      field :started_at, Types::TimeType,
        null: true,
        description: 'Timestamp of when the rollout started.'

      field :finished_at, Types::TimeType,
        null: true,
        description: 'Timestamp of when the rollout finished.'

      field :application, ::Types::Cd::ApplicationType,
        null: true,
        description: 'Application the rollout belongs to.'

      field :version_set, ::Types::Cd::VersionSetType,
        null: true,
        description: 'Version set the rollout deploys.'

      field :application_flow_definition, ::Types::Cd::ApplicationFlowDefinitionType,
        null: true,
        description: 'Flow definition the rollout was created from.',
        experiment: { milestone: '19.2' }

      field :rollout_environments, ::Types::Cd::RolloutEnvironmentType.connection_type,
        null: true,
        description: 'Rollout environments of the rollout.',
        resolver: ::Resolvers::Cd::RolloutEnvironmentsResolver,
        experiment: { milestone: '19.2' }

      # rubocop:disable GraphQL/ExtractType -- distinct rollout associations, not a logical sub-grouping
      field :rollout_transitions, ::Types::Cd::RolloutTransitionType.connection_type,
        null: true,
        description: 'Transition journal of the rollout.',
        resolver: ::Resolvers::Cd::RolloutTransitionsResolver,
        experiment: { milestone: '19.2' }

      # Plain list, not a connection: the flow definition tree is small and bounded, and the
      # frontend consumes it as a plain array (see Cd::RolloutSteps::Builder / the flow viz mock).
      field :rollout_steps, [::Types::Cd::RolloutStepType],
        null: true,
        description: 'Top-level nodes of the rollout flow definition tree, in position order. ' \
          'A stage node exposes its nested steps through its own `steps` field.',
        resolver: ::Resolvers::Cd::RolloutStepsResolver,
        experiment: { milestone: '19.3' }
      # rubocop:enable GraphQL/ExtractType

      field :created_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the rollout was created.'

      field :updated_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the rollout was last updated.'

      field :triggered_by_user, Types::UserType,
        null: true,
        description: 'User who triggered the rollout, derived from its transition journal. ' \
          'Null if the rollout was triggered by a non-user principal (for example, a policy or schedule).',
        experiment: { milestone: '19.3' }

      field :awaiting_approval, GraphQL::Types::Boolean,
        null: false,
        description: 'Indicates whether the rollout has an open approval gate awaiting a decision, ' \
          'derived from its transition journal.',
        experiment: { milestone: '19.3' }

      field :gates, [::Types::Cd::RolloutGateType],
        null: true,
        description: 'Approval gates recorded against the rollout, in the order they were opened, ' \
          'derived from its transition journal.',
        resolver: ::Resolvers::Cd::RolloutGatesResolver,
        experiment: { milestone: '19.4' }

      def awaiting_approval
        BatchLoader::GraphQL.for(object.id).batch do |rollout_ids, loader|
          open_gate_rollout_ids = ::Cd::RolloutTransition.open_gate_rollout_ids(rollout_ids).to_set

          rollout_ids.each { |rollout_id| loader.call(rollout_id, open_gate_rollout_ids.include?(rollout_id)) }
        end
      end

      def application
        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Cd::Application, object.application_id).find
      end

      def triggered_by_user
        BatchLoader::GraphQL.for(object.id).batch do |rollout_ids, loader|
          ::Cd::RolloutTransition.first_acting_user_id_by_rollout(rollout_ids).each do |rollout_id, user_id|
            loader.call(rollout_id, ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::User, user_id).find)
          end
        end
      end

      def version_set
        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Cd::VersionSet, object.version_set_id).find
      end

      def application_flow_definition
        return unless object.application_flow_definition_id

        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(
          ::Cd::ApplicationFlowDefinition, object.application_flow_definition_id).find
      end
    end
  end
end
