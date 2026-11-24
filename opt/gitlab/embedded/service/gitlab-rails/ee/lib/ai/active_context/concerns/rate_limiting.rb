# frozen_string_literal: true

module Ai
  module ActiveContext
    module Concerns
      module RateLimiting
        extend ActiveSupport::Concern

        protected

        def ad_hoc_indexing_rate_limited?(project)
          ::Gitlab::ApplicationRateLimiter.throttled?(
            :semantic_code_search_ad_hoc_indexing,
            scope: { namespace: project.root_namespace }
          )
        end
      end
    end
  end
end
