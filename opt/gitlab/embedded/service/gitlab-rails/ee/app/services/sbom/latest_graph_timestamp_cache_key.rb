# frozen_string_literal: true

module Sbom
  class LatestGraphTimestampCacheKey < BaseProjectService
    CACHE_EXPIRATION_TIME = 24.hours

    def store(timestamp)
      Rails.cache.write(cache_key, timestamp, expires_in: CACHE_EXPIRATION_TIME)
    end

    def retrieve
      Rails.cache.read(cache_key)
    end

    def cache_key
      "#{self.class}-latest-sbom-graph-timestamp-#{project.id}"
    end
  end
end
