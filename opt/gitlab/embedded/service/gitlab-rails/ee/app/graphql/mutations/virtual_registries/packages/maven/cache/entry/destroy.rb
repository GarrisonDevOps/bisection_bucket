# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Packages
      module Maven
        module Cache
          module Entry
            class Destroy < ::Mutations::VirtualRegistries::Cache::Entry::Destroy
              graphql_name 'MavenCacheEntryDelete'

              field :cache_entry,
                ::Types::VirtualRegistries::Packages::Maven::Cache::EntryType,
                null: true,
                description: 'Maven cache entry.'

              private

              def cache_entry_model
                ::VirtualRegistries::Packages::Maven::Cache::Remote::Entry
              end

              def available?(entry)
                ::VirtualRegistries::Packages::Maven.virtual_registry_available?(
                  entry.group, current_user, :destroy_virtual_registry
                )
              end
            end
          end
        end
      end
    end
  end
end
