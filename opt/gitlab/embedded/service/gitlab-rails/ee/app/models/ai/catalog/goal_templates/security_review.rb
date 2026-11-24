# frozen_string_literal: true

module Ai
  module Catalog
    module GoalTemplates
      class SecurityReview < Base
        def self.resolve(event_type:, resource:, user_input: nil, params: {}) # rubocop:disable Lint/UnusedMethodArgument -- interface contract from Base
          raise ArgumentError, 'resource must not be nil' unless resource

          # For all trigger types, return the resource URL as the goal.
          # The flow pipeline uses this to fetch the MR data.
          # For mention triggers, the validate_and_publish step will
          # detect developer replies in existing threads and respond.
          Gitlab::UrlBuilder.build(resource)
        end
      end
    end
  end
end
