# frozen_string_literal: true

module Gitlab
  module RateLimit
    module TierResolver
      class << self
        # Only a user resolves from the requester id. A deploy token also gets a
        # per-user budget now, but its plan comes from the namespace it belongs to,
        # so ClassifiedRequest#requester_plan routes it through namespace_tier_for
        # instead.
        def tier_for(requester_type, requester_id)
          return unless requester_type == 'user'

          ::GitlabSubscriptions::CachedPlanTier.for_user_id(requester_id)
        end

        def namespace_tier_for(root_namespace_id)
          ::GitlabSubscriptions::CachedPlanTier.for_root_namespace_id(root_namespace_id)
        end
      end
    end
  end
end
