# frozen_string_literal: true

module Types
  module ComplianceManagement
    module ComplianceFramework
      # rubocop: disable Graphql/AuthorizeTypes -- only accessible in group type and resolver authorizes group
      # rubocop: disable GraphQL/ExtractType -- no value for now
      class FrameworksNeedingAttentionType < ::Types::BaseObject
        graphql_name 'ComplianceFrameworksNeedingAttention'
        description 'Compliance framework requiring attention.'

        field :id, GraphQL::Types::ID,
          null: false, description: 'ID of the framework needing attention.'

        field :framework, ::Types::ComplianceManagement::ComplianceFrameworkType,
          null: false, description: 'Compliance framework needing attention.'

        field :projects_count, GraphQL::Types::Int,
          null: false, description: 'Number of projects with the framework applied.'

        field :requirements_count, GraphQL::Types::Int,
          null: false, description: 'Number of requirements in the framework.'

        field :requirements_without_controls, [Types::ComplianceManagement::ComplianceRequirementType],
          null: true, description: 'Requirements without controls.'

        def id
          Gitlab::GlobalId.build(model_name: 'ComplianceFrameworksNeedingAttention', id: object.id)
        end

        def framework
          object
        end

        def requirements_without_controls
          BatchLoader::GraphQL.for(object.id).batch(default_value: []) do |framework_ids, loader|
            ::ComplianceManagement::ComplianceFramework::ComplianceRequirement
              .for_framework(framework_ids)
              .without_controls
              .group_by(&:framework_id)
              .each do |framework_id, requirements|
              loader.call(framework_id, requirements)
            end
          end
        end

        # rubocop: enable Graphql/AuthorizeTypes
        # rubocop: enable GraphQL/ExtractType
      end
    end
  end
end
