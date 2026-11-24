# frozen_string_literal: true

module Types
  module VirtualRegistries
    module Container
      module Cache
        class EntryType < ::Types::BaseObject
          graphql_name 'ContainerUpstreamCacheEntry'
          description 'Represents a cache entry for an upstream container registry.'

          authorize :read_virtual_registry
          implements Types::VirtualRegistries::Cache::EntryInterface
        end
      end
    end
  end
end
