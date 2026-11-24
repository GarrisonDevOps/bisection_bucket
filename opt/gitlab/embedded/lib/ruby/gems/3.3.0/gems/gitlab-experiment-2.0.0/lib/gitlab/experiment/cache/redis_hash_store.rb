# frozen_string_literal: true

# This cache strategy is an implementation on top of the redis hash data type, that also adheres to the
# ActiveSupport::Cache::Store interface. It's a good example of how to build a custom caching strategy for
# Gitlab::Experiment, and is intended to be a long lived cache -- until the experiment is cleaned up.
#
# The data structure:
#   key: experiment.name
#   fields: context key => variant name
#
# Example configuration usage:
#
# config.cache = Gitlab::Experiment::Cache::RedisHashStore.new(
#   pool: ->(&block) { block.call(Redis.current) }
# )
#
module Gitlab
  class Experiment
    module Cache
      class RedisHashStore < ActiveSupport::Cache::Store
        # Clears the entire cache for a given experiment. Be careful with this since it would reset all resolved
        # variants for the entire experiment.
        def clear(key:)
          key = hkey(key)[0] # extract only the first part of the key
          pool do |redis|
            case redis.type(key)
            when 'hash', 'none'
              redis.del(key) # delete the primary experiment key
              redis.del("#{key}_attrs") # delete the experiment attributes key
            else raise ArgumentError, 'invalid call to clear a non-hash cache key'
            end
          end
        end

        def increment(key, amount = 1)
          pool { |redis| redis.hincrby(*hkey(key), amount) }
        end

        private

        def pool(&block)
          raise ArgumentError, 'missing block' unless block.present?

          @options[:pool].call(&block)
        end

        def hkey(key)
          key.to_s.split(':') # this assumes the default strategy in gitlab-experiment
        end

        def read_entry(key, **_options)
          value = pool { |redis| redis.hget(*hkey(key)) }
          value.nil? ? nil : ActiveSupport::Cache::Entry.new(value)
        end

        def write_entry(key, entry, **_options)
          return false if entry.value.blank? # don't cache any empty values

          pool { |redis| redis.hset(*hkey(key), entry.value) }
        end

        def delete_entry(key, **_options)
          pool { |redis| redis.hdel(*hkey(key)) }
        end
      end
    end
  end
end
