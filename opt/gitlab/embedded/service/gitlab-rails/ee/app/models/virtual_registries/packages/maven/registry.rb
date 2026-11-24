# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Maven
      class Registry < ::VirtualRegistries::Registry
        include Gitlab::Utils::StrongMemoize

        MAX_REGISTRY_COUNT = 20

        has_many :registry_upstreams,
          -> { order(position: :asc) },
          class_name: 'VirtualRegistries::Packages::Maven::RegistryUpstream',
          inverse_of: :registry
        has_many :upstreams,
          class_name: 'VirtualRegistries::Packages::Maven::Upstream',
          through: :registry_upstreams
        has_many :local_upstreams,
          class_name: 'VirtualRegistries::Packages::Maven::Local::Upstream',
          through: :registry_upstreams

        def all_upstreams
          registry_upstreams.includes(:upstream, :local_upstream).map(&:resolved_upstream)
        end
        strong_memoize_attr :all_upstreams
      end
    end
  end
end
