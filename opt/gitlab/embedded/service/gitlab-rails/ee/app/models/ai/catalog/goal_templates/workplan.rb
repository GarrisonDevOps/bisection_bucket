# frozen_string_literal: true

module Ai
  module Catalog
    module GoalTemplates
      # Goal template for the async "Generate workplan" foundational flow.
      #
      # The `workplan/v1` flow's system prompt (gitlab-ai-gateway) is the sole
      # source of truth for how the agent behaves - plan format, ambiguity
      # handling, the question-escalation protocol, and writing rules all
      # live there. This goal only needs to name the target work item;
      # restating any of that behavior here would just be a second copy to
      # keep in sync with the system prompt.
      class Workplan < Base
        TEMPLATE = 'Generate a workplan for the work item at %{work_item_url}.'

        def self.resolve(resource:, event_type: nil, user_input: nil, params: {}) # rubocop:disable Lint/UnusedMethodArgument -- interface contract from Base
          raise ArgumentError, 'resource must not be nil' unless resource

          interpolate(TEMPLATE, vars: { work_item_url: Gitlab::UrlBuilder.build(resource) })
        end
      end
    end
  end
end
