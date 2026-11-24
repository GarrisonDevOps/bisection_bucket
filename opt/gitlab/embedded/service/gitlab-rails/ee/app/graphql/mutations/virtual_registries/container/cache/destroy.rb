# frozen_string_literal: true

module Mutations
  module VirtualRegistries
    module Container
      module Cache
        # rubocop:disable GraphQL/GraphqlName -- Base class needs no name.
        class Destroy < ::Mutations::VirtualRegistries::Cache::Destroy
          private

          def available?(object)
            ::VirtualRegistries::Container.virtual_registry_available?(
              object.group, current_user, :destroy_virtual_registry
            )
          end
        end
        # rubocop:enable GraphQL/GraphqlName
      end
    end
  end
end
