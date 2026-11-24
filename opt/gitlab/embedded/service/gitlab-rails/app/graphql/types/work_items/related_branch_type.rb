# frozen_string_literal: true

module Types
  module WorkItems
    # Disabling widget level authorization as it might be too granular
    # and we already authorize the parent work item
    # rubocop:disable Graphql/AuthorizeTypes -- reason above
    class RelatedBranchType < BaseObject
      graphql_name 'WorkItemRelatedBranch'

      # Branch names, and the default branch in compare_path, are read_branch data, as on the Branch type.
      authorize_granular_token parent_authorizes: :read_branch

      field :name,
        GraphQL::Types::String,
        null: false,
        description: 'Name of the branch.'

      field :compare_path, GraphQL::Types::String, null: true,
        description: 'Path to comparison of branch to default branch.'

      field :pipeline_status, ::Types::Ci::DetailedStatusType, null: true,
        description: 'Status of pipeline for the branch.'
    end
    # rubocop:enable Graphql/AuthorizeTypes
  end
end
