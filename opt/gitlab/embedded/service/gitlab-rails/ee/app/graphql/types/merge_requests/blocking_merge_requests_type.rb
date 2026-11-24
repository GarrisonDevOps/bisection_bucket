# frozen_string_literal: true

module Types
  module MergeRequests
    class BlockingMergeRequestsType < ::Types::BaseObject
      graphql_name 'BlockingMergeRequests'
      description 'Information about the rules that must be satisfied to merge this merge request.'

      authorize :read_merge_request

      # The permission the REST merge request dependency routes ask for. Blockers can sit
      # in other projects: MergeRequest checks the token on each one.
      authorize_granular_token permissions: :read_merge_request_dependency, boundary: :project, boundary_type: :project

      field :hidden_count, GraphQL::Types::Int,
        null: false,
        description: "Blocking merge requests not visible to the user."

      field :total_count, GraphQL::Types::Int,
        null: false,
        description: 'Total number of blocking merge requests.'

      field :visible_merge_requests,
        [::Types::MergeRequestType],
        null: true,
        description: 'Blocking merge requests visible to the user.',
        max_page_size: 20

      def hidden_count
        object.hidden_blocking_merge_requests_count(current_user)
      end

      def visible_merge_requests
        object.visible_blocking_merge_requests(current_user)
      end

      def total_count
        visible_merge_requests.count + hidden_count
      end
    end
  end
end
