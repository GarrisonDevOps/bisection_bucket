# frozen_string_literal: true

module Types
  module Ci
    class PipelineMinimalAccessType < BaseObject
      graphql_name 'PipelineMinimalAccess'

      implements PipelineInterface

      authorize :read_pipeline_metadata

      field :id, GraphQL::Types::ID, null: false,
        description: 'ID of the pipeline.'
      field :project, Types::Projects::ProjectInterface, null: true,
        description: 'Project the pipeline belongs to.'
      field :user,
        type: 'Types::UserType',
        null: true,
        description: 'Pipeline user.'
    end
  end
end
