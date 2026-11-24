# frozen_string_literal: true

module Resolvers
  module VirtualRegistries
    module Container
      module Cache
        class EntriesResolver < ::Resolvers::VirtualRegistries::Cache::EntriesResolver
          type ::Types::VirtualRegistries::Container::Cache::EntryType.connection_type, null: true

          private

          def virtual_registry_available?
            ::VirtualRegistries::Container.virtual_registry_available?(
              upstream.group, current_user
            )
          end
        end
      end
    end
  end
end
