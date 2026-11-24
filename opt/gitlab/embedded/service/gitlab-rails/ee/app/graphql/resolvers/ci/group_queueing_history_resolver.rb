# frozen_string_literal: true

module Resolvers
  module Ci
    # rubocop:disable Graphql/ResolverType -- the type is inherited from the parent class
    class GroupQueueingHistoryResolver < BaseQueueingHistoryResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      authorize :read_jobs_statistics

      description <<~MD
        Time taken for CI jobs to be picked up by this group's runners by percentile.
        Available to group maintainers.
      MD

      alias_method :group, :object

      def resolve(lookahead:, from_time: nil, to_time: nil)
        authorize! group

        super(lookahead: lookahead, from_time: from_time, to_time: to_time,
              runner_type: :GROUP_TYPE, owner_namespace: group)
      end
    end
    # rubocop:enable Graphql/ResolverType
  end
end
