# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Npm
      class Registry < ::VirtualRegistries::Registry
        MAX_REGISTRY_COUNT = 20

        has_many :registry_upstreams,
          -> { order(position: :asc) },
          class_name: 'VirtualRegistries::Packages::Npm::RegistryUpstream',
          inverse_of: :registry
        has_many :upstreams,
          class_name: 'VirtualRegistries::Packages::Npm::Upstream',
          through: :registry_upstreams
      end
    end
  end
end
