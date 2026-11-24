# frozen_string_literal: true

module Types
  module VirtualRegistries
    module Packages
      module Maven
        module Cache
          # rubocop: disable Graphql/AuthorizeTypes -- authorization handled by parent UpstreamType
          class EntryType < ::Types::BaseObject
            graphql_name 'MavenUpstreamCacheEntry'
            description 'Represents a cache entry for a Maven upstream.'

            implements Types::VirtualRegistries::Cache::EntryInterface
          end
          # rubocop: enable Graphql/AuthorizeTypes
        end
      end
    end
  end
end
