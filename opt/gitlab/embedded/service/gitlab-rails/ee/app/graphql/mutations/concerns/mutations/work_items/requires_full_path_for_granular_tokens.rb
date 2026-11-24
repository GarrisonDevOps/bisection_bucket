# frozen_string_literal: true

module Mutations
  module WorkItems
    module RequiresFullPathForGranularTokens
      extend ActiveSupport::Concern

      GRANULAR_TOKEN_FULL_PATH_ERROR =
        'fullPath is required when authenticating with a fine-grained personal access token'

      # Without fullPath these mutations fall back to the current organization, which has no
      # granular token boundary, so the framework check would deny with an opaque 404.
      def ready?(**args)
        if args[:full_path].blank? && context[:access_token].try(:granular?)
          raise ::Gitlab::Graphql::Errors::ArgumentError, GRANULAR_TOKEN_FULL_PATH_ERROR
        end

        super
      end
    end
  end
end
