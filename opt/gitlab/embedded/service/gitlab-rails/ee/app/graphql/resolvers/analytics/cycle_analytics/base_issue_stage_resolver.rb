# frozen_string_literal: true

# rubocop:disable Graphql/ResolverType -- inherited from Resolvers::Analytics::CycleAnalytics::BaseIssueResolver
module Resolvers
  module Analytics
    module CycleAnalytics
      class BaseIssueStageResolver < BaseIssueResolver
        include ::Resolvers::Analytics::CycleAnalytics::Concerns::IssuableStageResolver
      end
    end
  end
end
# rubocop:enable Graphql/ResolverType
