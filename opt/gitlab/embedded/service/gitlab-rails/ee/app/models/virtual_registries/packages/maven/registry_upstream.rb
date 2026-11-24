# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Maven
      class RegistryUpstream < ::VirtualRegistries::RegistryUpstream
        MAX_UPSTREAMS_COUNT = 20
        UPSTREAMS_MUTUALLY_EXCLUSIVE_ERROR = 'should only have either the (remote) upstream or local upstream set'

        belongs_to :registry,
          class_name: 'VirtualRegistries::Packages::Maven::Registry',
          inverse_of: :registry_upstreams
        belongs_to :upstream,
          class_name: 'VirtualRegistries::Packages::Maven::Upstream',
          inverse_of: :registry_upstreams
        belongs_to :local_upstream,
          class_name: 'VirtualRegistries::Packages::Maven::Local::Upstream',
          inverse_of: :registry_upstreams

        validates :local_upstream_id, uniqueness: { scope: :registry_id }, if: :local_upstream_id?
        validate :ensure_upstream_or_local_upstream

        def resolved_upstream
          upstream || local_upstream
        end

        private

        def ensure_upstream_or_local_upstream
          return if upstream.present? ^ local_upstream.present?

          errors.add(:base, UPSTREAMS_MUTUALLY_EXCLUSIVE_ERROR)
        end
      end
    end
  end
end
