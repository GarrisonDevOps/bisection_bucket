# frozen_string_literal: true

module VirtualRegistries
  module Upstreams
    module Remote
      # Shared redirect-following rules for the two credential-safe followers:
      # RedirectHandler (async Typhoeus/Hydra) and CredentialSafeHeadRequest (sync Gitlab::HTTP).
      # Owns the redirect status codes, the hop limit, and the `redirect?` predicate; each
      # class keeps its own hop-counting since the sync loop and async continuation differ.
      module RedirectRules
        MAX_REDIRECTS = 5
        REDIRECT_STATUS_CODES = [301, 302, 303, 307, 308].freeze

        def redirect?(response)
          REDIRECT_STATUS_CODES.include?(response.code)
        end
      end
    end
  end
end
