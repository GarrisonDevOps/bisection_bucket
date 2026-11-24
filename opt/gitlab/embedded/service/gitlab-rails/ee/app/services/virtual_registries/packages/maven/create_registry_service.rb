# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Maven
      class CreateRegistryService < ::VirtualRegistries::CreateRegistryService
        private

        def unavailable_message
          s_('VirtualRegistry|Maven virtual registry not available')
        end

        def registry_class
          ::VirtualRegistries::Packages::Maven::Registry
        end

        def availability_class
          ::VirtualRegistries::Packages::Maven
        end
      end
    end
  end
end
