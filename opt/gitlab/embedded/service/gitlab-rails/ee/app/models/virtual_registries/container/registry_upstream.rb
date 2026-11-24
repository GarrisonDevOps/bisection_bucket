# frozen_string_literal: true

module VirtualRegistries
  module Container
    class RegistryUpstream < ::VirtualRegistries::RegistryUpstream
      MAX_UPSTREAMS_COUNT = 5

      belongs_to :registry,
        class_name: '::VirtualRegistries::Container::Registry',
        inverse_of: :registry_upstreams
      belongs_to :upstream,
        class_name: '::VirtualRegistries::Container::Upstream',
        inverse_of: :registry_upstreams
    end
  end
end
