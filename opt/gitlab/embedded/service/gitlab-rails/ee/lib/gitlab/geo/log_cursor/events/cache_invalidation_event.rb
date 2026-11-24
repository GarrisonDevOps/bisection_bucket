# frozen_string_literal: true

module Gitlab
  module Geo
    module LogCursor
      module Events
        class CacheInvalidationEvent
          include BaseEvent

          def process
            result = expire_cache_for_event_key
            log_cache_invalidation_event(result)
          end

          private

          def expire_cache_for_event_key
            # This event's key can come from two distinct cache producers:
            # a generic Rails.cache.delete (e.g. BaseCountService) or a
            # feature flag change, which is cached separately in
            # Feature.l2_cache_backend and may live on its own Redis
            # instance. Expire both so neither producer is left stale.
            # See https://gitlab.com/gitlab-org/gitlab/-/issues/260456
            [
              expire_generic_redis_cache,
              expire_feature_flag_redis_cache
            ].any?
          end

          def expire_generic_redis_cache
            Rails.cache.delete(event.key)
          end

          def expire_feature_flag_redis_cache
            Feature.l2_cache_backend.delete(event.key)
          end

          def log_cache_invalidation_event(expired)
            log_event(
              'Cache invalidation',
              cache_key: event.key,
              cache_expired: expired,
              skippable: false
            )
          end
        end
      end
    end
  end
end
