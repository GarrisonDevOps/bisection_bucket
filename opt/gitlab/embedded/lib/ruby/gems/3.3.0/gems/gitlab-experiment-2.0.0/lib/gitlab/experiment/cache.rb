# frozen_string_literal: true

module Gitlab
  class Experiment
    module Cache
      autoload :RedisHashStore, 'gitlab/experiment/cache/redis_hash_store.rb'

      class Interface
        attr_reader :store, :key

        def initialize(experiment, store)
          @experiment = experiment
          @store = store
          @key = experiment.cache_key
        end

        def read
          store.read(key)
        end

        def write(value = nil)
          store.write(key, value || @experiment.assigned.name)
        end

        def delete
          store.delete(key)
        end

        def attr_get(name)
          store.read(@experiment.cache_key(name, suffix: :attrs))
        end

        def attr_set(name, value)
          store.write(@experiment.cache_key(name, suffix: :attrs), value)
        end

        def attr_inc(name, amount = 1)
          store.increment(@experiment.cache_key(name, suffix: :attrs), amount)
        end
      end

      def cache
        @cache ||= Interface.new(self, Configuration.cache)
      end

      def cache_variant(specified = nil, &)
        return (specified.presence || yield) unless cache.store

        result = migrated_cache_fetch(cache.store) || find_variant(&)
        return result unless specified.present?

        cache.write(specified) if result.to_s != specified.to_s
        specified
      end

      def find_variant(&)
        cache.store.fetch(cache_key, &)
      end

      def cache_key(key = nil, suffix: nil)
        "#{[name, suffix].compact.join('_')}:#{key || context.signature[:key]}"
      end

      private

      def migrated_cache_fetch(store)
        migrations = context.signature[:migration_keys]&.map { |key| cache_key(key) } || []
        migrations.find do |old_key|
          value = store.read(old_key)

          next unless value

          store.write(cache_key, value)
          store.delete(old_key)
          break value
        end
      end
    end
  end
end
