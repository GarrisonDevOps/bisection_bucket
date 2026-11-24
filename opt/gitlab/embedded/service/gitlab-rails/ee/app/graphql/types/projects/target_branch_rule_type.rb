# frozen_string_literal: true

module Types
  module Projects
    class TargetBranchRuleType < BaseObject
      graphql_name 'ProjectTargetBranchRule'

      connection_type_class Types::CountableConnectionType

      authorize :read_target_branch_rule
      authorize_granular_token permissions: :read_target_branch_rule, boundary: :project, boundary_type: :project

      field :created_at, Types::TimeType, null: false,
        description: 'Timestamp of when the target branch rule was created.'
      field :id, ::Types::GlobalIDType[::Projects::TargetBranchRule],
        null: false,
        description: 'ID of the target branch rule.'
      field :name, GraphQL::Types::String,
        null: false,
        description: 'Name of the target branch rule.'
      field :target_branch, GraphQL::Types::String,
        null: false,
        description: 'Target branch for the target branch rule.'
    end
  end
end
