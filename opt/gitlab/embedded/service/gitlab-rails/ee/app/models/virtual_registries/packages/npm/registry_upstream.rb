# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Npm
      class RegistryUpstream < ::VirtualRegistries::RegistryUpstream
        MAX_UPSTREAMS_COUNT = 20

        belongs_to :registry,
          class_name: '::VirtualRegistries::Packages::Npm::Registry',
          inverse_of: :registry_upstreams
        belongs_to :upstream,
          class_name: '::VirtualRegistries::Packages::Npm::Upstream',
          inverse_of: :registry_upstreams
      end
    end
  end
end
