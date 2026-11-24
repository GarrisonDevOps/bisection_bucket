# frozen_string_literal: true

module GitlabSubscriptions
  module FreeGroupUpgradeLinkCache
    CACHE_EXPIRATION = 10.minutes

    def self.get(user_id)
      Rails.cache.fetch(cache_key(user_id), expires_in: CACHE_EXPIRATION) do
        yield
      end
    end

    def self.invalidate(user_id)
      Rails.cache.delete(cache_key(user_id))
    end

    def self.cache_key(user_id)
      ['users', user_id, 'free_group_upgrade_link']
    end

    private_class_method :cache_key
  end
end
