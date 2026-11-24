# frozen_string_literal: true

module Resolvers
  module Analytics
    module AiUsage
      class InstanceUsageEventsResolver < UsageEventsResolver # rubocop:disable Graphql/ResolverType -- declared just below. false positive.
        type ::Types::Analytics::AiUsage::AiInstanceUsageEventType.connection_type, null: true
      end
    end
  end
end
