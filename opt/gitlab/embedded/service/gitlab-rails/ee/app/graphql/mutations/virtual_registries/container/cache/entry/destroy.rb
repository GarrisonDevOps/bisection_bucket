# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Container
      module Cache
        module Entry
          class Destroy < ::Mutations::VirtualRegistries::Cache::Entry::Destroy
            graphql_name 'ContainerCacheEntryDelete'

            field :cache_entry,
              ::Types::VirtualRegistries::Container::Cache::EntryType,
              null: true,
              description: 'Deleted container cache entry.'

            private

            def cache_entry_model
              ::VirtualRegistries::Container::Cache::Remote::Entry
            end

            def available?(entry)
              ::VirtualRegistries::Container.virtual_registry_available?(
                entry.group, current_user, :destroy_virtual_registry
              )
            end
          end
        end
      end
    end
  end
end
