# frozen_string_literal: true

module Types
  module Ci
    # rubocop: disable Graphql/AuthorizeTypes -- the read_runner_usage permission is already checked by the resolver
    class RunnerUsageType < BaseObject
      graphql_name 'CiRunnerUsage'
      description 'Runner usage in minutes.'

      field :runner, ::Types::Ci::RunnerType,
        null: true, description: 'Runner that the usage refers to. Null means "Other runners".'

      field :ci_duration, GraphQL::Types::BigInt,
        null: false,
        description: 'Number of minutes spent to process jobs during the selected period. Encoded as a string.',
        hash_key: :ci_minutes_used

      # TODO: Remove in 18.0. For more details read https://gitlab.com/gitlab-org/gitlab/-/issues/497364
      field :ci_minutes_used, GraphQL::Types::BigInt,
        null: false, description: 'Amount of minutes used during the selected period. Encoded as a string.',
        deprecated: { reason: 'Use `ciDuration`', milestone: '17.5' }

      field :ci_build_count, GraphQL::Types::BigInt,
        null: false, description: 'Amount of builds executed during the selected period. Encoded as a string.'

      def runner
        return unless object[:runner_id]

        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Ci::Runner, object[:runner_id]).find
      end
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
