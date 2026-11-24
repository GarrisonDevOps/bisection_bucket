# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Maven
      class DestroyRegistryUpstreamService < ::VirtualRegistries::DestroyRegistryUpstreamService
        private

        def available?
          ::VirtualRegistries::Packages::Maven.virtual_registry_available?(
            registry_upstream.group,
            current_user,
            :destroy_virtual_registry
          )
        end
      end
    end
  end
end
