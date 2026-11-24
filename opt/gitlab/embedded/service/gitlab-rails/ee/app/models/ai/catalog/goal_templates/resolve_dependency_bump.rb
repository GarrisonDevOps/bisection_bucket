# frozen_string_literal: true

module Ai
  module Catalog
    module GoalTemplates
      class ResolveDependencyBump < Base
        def self.resolve(event_type:, resource:, user_input: nil, params: {}) # rubocop:disable Lint/UnusedMethodArgument -- interface contract from Base
          raise ArgumentError, 'resource must not be nil' unless resource

          # Return the mentioned resource (merge request) URL as the goal. The
          # flow locates the failed dependency-bump pipeline from the merge request.
          Gitlab::UrlBuilder.build(resource)
        end
      end
    end
  end
end
