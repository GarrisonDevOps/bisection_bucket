# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Maven
      module Local
        module Upstreams
          class UpdateService < ::VirtualRegistries::Packages::Maven::Local::Upstreams::BaseService
            alias_method :upstream, :container

            def initialize(upstream:, current_user: nil, params: {})
              super(container: upstream, current_user: current_user, params: params)
            end

            private

            def process_upstream
              upstream.tap { |u| u.assign_attributes(upstream_params) }
            end

            def allowed?
              can?(current_user, :update_virtual_registry, upstream)
            end
          end
        end
      end
    end
  end
end
