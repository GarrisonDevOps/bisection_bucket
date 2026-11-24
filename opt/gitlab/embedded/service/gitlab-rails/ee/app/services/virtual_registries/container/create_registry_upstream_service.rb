# frozen_string_literal: true

module VirtualRegistries
  module Container
    class CreateRegistryUpstreamService < ::VirtualRegistries::CreateRegistryUpstreamService
      private

      def registry_upstream_class
        ::VirtualRegistries::Container::RegistryUpstream
      end

      def available?
        ::VirtualRegistries::Container.virtual_registry_available?(registry.group, current_user)
      end
    end
  end
end
