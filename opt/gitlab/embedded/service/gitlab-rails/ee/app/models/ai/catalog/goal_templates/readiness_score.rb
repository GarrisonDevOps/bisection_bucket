# frozen_string_literal: true

module Ai
  module Catalog
    module GoalTemplates
      # The flow's fetch step feeds the goal straight into get_work_item, so it
      # must be a bare work item URL - prose would break URL parsing.
      class ReadinessScore < Base
        TEMPLATE = '%{work_item_url}'

        def self.resolve(resource:, event_type: nil, user_input: nil, params: {}) # rubocop:disable Lint/UnusedMethodArgument -- interface contract from Base
          raise ArgumentError, 'resource must not be nil' unless resource

          interpolate(TEMPLATE, vars: { work_item_url: Gitlab::UrlBuilder.build(resource) })
        end
      end
    end
  end
end
