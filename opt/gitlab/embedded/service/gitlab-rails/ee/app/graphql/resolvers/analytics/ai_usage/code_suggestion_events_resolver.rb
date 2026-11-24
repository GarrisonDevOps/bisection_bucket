# frozen_string_literal: true

module Resolvers
  module Analytics
    module AiUsage
      class CodeSuggestionEventsResolver < UsageEventsResolver
        type ::Types::Analytics::AiUsage::CodeSuggestionEventType.connection_type, null: true

        def params_with_defaults(args)
          super.merge(events: Gitlab::Tracking::AiTracking.registered_events(:code_suggestions).keys)
        end
      end
    end
  end
end
