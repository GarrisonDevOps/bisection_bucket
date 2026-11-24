# frozen_string_literal: true

module SecretsManagement
  class Entitlement
    # Keeps CustomersDot's last successful answer so a transport failure extends
    # the access CDot already granted instead of denying it.
    #
    # Holds the two raw CDot responses, not the merged entitlement, so that
    # `Resolver#grace_window_reason` re-derives the subscription grace window
    # against today rather than replaying a window that has since lapsed.
    #
    # SharedState rather than Rails.cache: the cache instance is
    # eviction-eligible (doc/development/redis.md), and an evicted slot is
    # indistinguishable from an expired one.
    class LastKnownGoodStore
      WINDOW = 24.hours
      CACHE_NAMESPACE = 'secrets_management:entitlement:lkg'

      # Named subclass so cache metrics can tell this store from the others --
      # Gitlab::Metrics::Subscribers::RailsCache labels by the class basename.
      LastKnownGoodCacheStore = Class.new(ActiveSupport::Cache::RedisCacheStore)

      Record = Data.define(:trial, :resolve, :resolved_at)

      TRIAL_RESPONSE = ::Gitlab::SubscriptionPortal::SecretsManagerTrialResponse
      RESOLVE_RESPONSE = ::Gitlab::SubscriptionPortal::SecretsManagerConsumerResolveResponse

      class << self
        # Absent, expired and unusable all return nil -- the caller treats them
        # the same and falls back to failing closed.
        def read(key)
          raw = cache_store.read(key)
          return unless raw.is_a?(Hash)

          trial = rebuild(TRIAL_RESPONSE, raw[:trial])
          resolve = rebuild(RESOLVE_RESPONSE, raw[:resolve])
          return unless trial && resolve

          Record.new(trial: trial, resolve: resolve, resolved_at: raw[:resolved_at])
        end

        def write(key, trial:, resolve:)
          cache_store.write(
            key,
            { trial: trial.to_h, resolve: resolve.to_h, resolved_at: Time.current }
          )
        end

        def delete(key)
          cache_store.delete(key)
        end

        private

        # Keeps only fields the class still declares, so a slot written before a
        # field was renamed or dropped is a miss rather than an exception.
        def rebuild(klass, attributes)
          return unless attributes.is_a?(Hash)

          klass.new(**attributes.slice(*klass.members))
        rescue ArgumentError
          nil
        end

        def cache_store
          @cache_store ||= LastKnownGoodCacheStore.new(
            redis: ::Gitlab::Redis::SharedState.pool,
            pool: false,
            namespace: CACHE_NAMESPACE,
            expires_in: WINDOW
          )
        end
      end
    end
  end
end
