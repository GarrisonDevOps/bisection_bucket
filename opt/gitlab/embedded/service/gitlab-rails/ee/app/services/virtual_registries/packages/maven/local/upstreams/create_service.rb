# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Maven
      module Local
        module Upstreams
          class CreateService < ::VirtualRegistries::Packages::Maven::Local::Upstreams::BaseService
            alias_method :registry, :container

            def initialize(registry:, current_user: nil, params: {})
              super(container: registry, current_user: current_user, params: params)
            end

            private

            def process_upstream
              registry.local_upstreams.build(upstream_params.merge(group: registry.group))
            end

            def allowed?
              can?(current_user, :create_virtual_registry, registry)
            end
          end
        end
      end
    end
  end
end
