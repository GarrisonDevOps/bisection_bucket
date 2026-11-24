# frozen_string_literal: true

module Types
  module Cd
    class RolloutStepType < ::Types::BaseObject
      graphql_name 'CdRolloutStep'
      description 'Node in a continuous deployment rollout flow definition tree.'

      connection_type_class Types::CountableConnectionType

      authorize :read_cd_rollout
      authorize_granular_token permissions: :read_cd_rollout,
        boundaries: [
          { boundary: :instance, boundary_type: :instance }
        ]

      field :id, Types::GlobalIDType[::Cd::RolloutStep],
        null: false,
        description: 'Global ID of the rollout step.'

      field :path, GraphQL::Types::String,
        null: false,
        description: 'Position of the step in the flow definition tree (for example "0", "0.1").'

      field :parent_path, GraphQL::Types::String,
        null: true,
        description: 'Path of the parent step, null for a top-level step.'

      field :step_type, GraphQL::Types::String,
        null: false,
        description: 'Type of the step, as defined by the flow definition (for example ' \
          '"com.gitlab.cd.steps.stage" or a deploy driver step type).'

      field :name, GraphQL::Types::String,
        null: true,
        description: 'Name of the step, as defined by the flow definition.'

      # rubocop:disable Graphql/JSONType -- params is genuinely unstructured: its shape depends on step_type,
      # copied verbatim from the flow definition (see Cd::RolloutSteps::Builder)
      field :params, GraphQL::Types::JSON,
        null: true,
        description: 'Step-specific configuration copied from the flow definition (for example wait seconds ' \
          'or canary service weights).'
      # rubocop:enable Graphql/JSONType

      field :environment, ::Types::Cd::EnvironmentType,
        null: true,
        description: 'Environment the step targets, null for steps that target no environment (for example ' \
          'a stage container or a wait step).'

      field :state, ::Types::Cd::RolloutStepStateEnum,
        null: false,
        description: 'State of the step.'

      field :started_at, Types::TimeType,
        null: true,
        description: 'Timestamp of when the step started.'

      field :finished_at, Types::TimeType,
        null: true,
        description: 'Timestamp of when the step finished.'

      field :error, GraphQL::Types::String,
        null: true,
        description: 'Error message of the step, if it failed.'

      field :steps, [::Types::Cd::RolloutStepType],
        null: true,
        description: 'Nested steps, for a stage step. Empty for any other step type.'

      field :created_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the step was created.'

      field :updated_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the step was last updated.'

      # Two lazy hops so the terminal fetch shares Cd::Environment's own batch key
      # (the same one RolloutEnvironmentType#environment uses), instead of pulling
      # in whole Cd::RolloutEnvironment records just to read their environment_id.
      def environment
        return unless object.rollout_environment_id

        lazy_environment_id = BatchLoader::GraphQL.for(object.rollout_environment_id).batch do |ids, loader|
          ::Cd::RolloutEnvironment.environment_ids_by_id(ids).each do |id, environment_id|
            loader.call(id, environment_id)
          end
        end

        ::Gitlab::Graphql::Lazy.with_value(lazy_environment_id) do |environment_id|
          next unless environment_id

          ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Cd::Environment, environment_id).find
        end
      end

      # Batched across every stage-type step in the response: one query fetches
      # every step's children regardless of how many stages are being resolved.
      def steps
        BatchLoader::GraphQL.for(object).batch do |stage_steps, loader|
          rollout_ids = stage_steps.map(&:rollout_id).uniq
          children_by_parent = ::Cd::RolloutStep.nested_grouped_by_parent(rollout_ids)

          stage_steps.each do |stage_step|
            loader.call(stage_step, children_by_parent[[stage_step.rollout_id, stage_step.path]] || [])
          end
        end
      end
    end
  end
end
