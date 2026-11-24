# frozen_string_literal: true

module Resolvers
  module Ci
    # rubocop:disable Graphql/ResolverType -- the type is inherited from the parent class
    class InstanceQueueingHistoryResolver < BaseQueueingHistoryResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      authorize :read_jobs_statistics

      description <<~MD
        Time taken for CI jobs to be picked up by runner by percentile. Available only to admins.
      MD

      argument :runner_type, ::Types::Ci::RunnerTypeEnum,
        required: false,
        description: 'Filter jobs by the type of runner that executed them.'

      def resolve(lookahead:, from_time: nil, to_time: nil, runner_type: nil)
        authorize! :global

        super
      end
    end
    # rubocop:enable Graphql/ResolverType
  end
end
