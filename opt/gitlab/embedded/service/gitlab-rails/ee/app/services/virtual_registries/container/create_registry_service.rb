# frozen_string_literal: true

module VirtualRegistries
  module Container
    class CreateRegistryService < ::VirtualRegistries::CreateRegistryService
      private

      def unavailable_message
        s_('VirtualRegistry|Container virtual registry not available')
      end

      def registry_class
        ::VirtualRegistries::Container::Registry
      end

      def availability_class
        ::VirtualRegistries::Container
      end
    end
  end
end
