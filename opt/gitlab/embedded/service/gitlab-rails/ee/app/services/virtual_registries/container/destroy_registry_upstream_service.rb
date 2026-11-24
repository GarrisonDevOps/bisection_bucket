# frozen_string_literal: true

module VirtualRegistries
  module Container
    class DestroyRegistryUpstreamService < ::VirtualRegistries::DestroyRegistryUpstreamService
      private

      def available?
        ::VirtualRegistries::Container.virtual_registry_available?(
          registry_upstream.group, current_user, :destroy_virtual_registry
        )
      end
    end
  end
end
