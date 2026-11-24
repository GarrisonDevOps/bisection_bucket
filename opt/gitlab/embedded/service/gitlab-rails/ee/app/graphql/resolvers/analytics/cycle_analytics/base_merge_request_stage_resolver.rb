# frozen_string_literal: true

# rubocop:disable Graphql/ResolverType -- inherited from Resolvers::Analytics::CycleAnalytics::BaseMergeRequestResolver
module Resolvers
  module Analytics
    module CycleAnalytics
      class BaseMergeRequestStageResolver < BaseMergeRequestResolver
        include ::Resolvers::Analytics::CycleAnalytics::Concerns::IssuableStageResolver
      end
    end
  end
end
# rubocop:enable Graphql/ResolverType
