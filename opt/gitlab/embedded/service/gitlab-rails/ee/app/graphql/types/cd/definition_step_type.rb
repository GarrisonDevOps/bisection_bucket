# frozen_string_literal: true

module Types
  module Cd
    class DefinitionStepType < ::Types::BaseObject
      graphql_name 'CdDefinitionStep'
      description 'Node in a continuous deployment flow definition step tree, computed from its YAML and ' \
        'not persisted.'

      connection_type_class Types::CountableConnectionType

      authorize :read_cd_application_flow_definition
      authorize_granular_token permissions: :read_cd_application_flow_definition,
        boundaries: [
          { boundary: :instance, boundary_type: :instance }
        ]

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

      # rubocop:disable Graphql/JSONType -- params is genuinely unstructured: its shape depends on step_type
      field :params, GraphQL::Types::JSON,
        null: true,
        description: 'Step-specific configuration copied from the flow definition (for example wait seconds ' \
          'or canary service weights).'
      # rubocop:enable Graphql/JSONType

      field :environment, ::Types::Cd::EnvironmentType,
        null: true,
        description: 'Environment the step targets, null for steps that target no environment (for example ' \
          'a stage container or a wait step) or that name an environment that does not exist.'

      field :steps, [::Types::Cd::DefinitionStepType],
        null: true,
        description: 'Nested steps, for a stage step. Empty for any other step type.'

      # Batched across every node of every flow definition being resolved in the response
      # (keyed by organization_id + name), so previewing many flow definitions' steps costs
      # one query total rather than one per flow definition (cf. object.environment_name,
      # set by Cd::ApplicationFlowDefinitions::DefinitionSteps::Builder without querying).
      def environment
        return unless object.environment_name

        BatchLoader::GraphQL.for([object.organization_id, object.environment_name]).batch do |keys, loader|
          organization_ids, names = keys.each_with_object([[], []]) do |(org_id, name), (orgs, name_list)|
            orgs << org_id
            name_list << name
          end

          ::Cd::Environment.in_organization(organization_ids).with_name(names).find_each do |environment|
            loader.call([environment.organization_id, environment.name], environment)
          end
        end
      end
    end
  end
end
