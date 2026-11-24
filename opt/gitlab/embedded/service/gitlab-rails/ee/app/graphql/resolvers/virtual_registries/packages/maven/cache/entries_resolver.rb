# frozen_string_literal: true

module Resolvers
  module VirtualRegistries
    module Packages
      module Maven
        module Cache
          class EntriesResolver < ::Resolvers::VirtualRegistries::Cache::EntriesResolver
            type ::Types::VirtualRegistries::Packages::Maven::Cache::EntryType.connection_type, null: true

            private

            def virtual_registry_available?
              ::VirtualRegistries::Packages::Maven.virtual_registry_available?(
                upstream.group, current_user
              )
            end
          end
        end
      end
    end
  end
end
