# frozen_string_literal: true

module Resolvers
  module MergeRequests
    class CommitsResolver < BaseResolver
      type ::Types::Repositories::CommitType.connection_type, null: true

      alias_method :merge_request, :object

      def resolve
        diff = merge_request.merge_request_diff
        return merge_request.commits(load_from_gitaly: true).commits unless diff.persisted?

        total = diff.commits_count.to_i.nonzero? || diff.merge_request_diff_commits.count
        loader = ->(offset, limit) { diff.commits_window(offset: offset, limit: limit) }

        ::Gitlab::Graphql::WindowedArray.new(total, loader)
      end
    end
  end
end
