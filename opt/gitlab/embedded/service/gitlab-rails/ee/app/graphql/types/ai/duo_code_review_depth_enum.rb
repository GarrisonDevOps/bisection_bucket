# frozen_string_literal: true

module Types
  module Ai
    class DuoCodeReviewDepthEnum < BaseEnum
      graphql_name 'DuoCodeReviewDepth'
      description 'Depth of a GitLab Duo Code Review.'

      value 'LITE', value: ::Gitlab::Duo::CodeReview::LITE_DEPTH,
        description: 'Lite review.'
      value 'STANDARD', value: ::Gitlab::Duo::CodeReview::STANDARD_DEPTH,
        description: 'Standard review.'
    end
  end
end
