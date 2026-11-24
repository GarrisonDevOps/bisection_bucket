# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Maven
      class DestroyUpstreamService < ::BaseContainerService
        alias_method :upstream, :container

        def initialize(upstream:, current_user:)
          super(container: upstream, current_user: current_user)
        end

        def execute
          unless ::VirtualRegistries::Packages::Maven.virtual_registry_available?(upstream.group, current_user,
            :destroy_virtual_registry)
            return ServiceResponse.error(
              message: s_('VirtualRegistry|Maven virtual registry not available'), reason: :unavailable
            )
          end

          upstream.transaction do
            ::VirtualRegistries::Packages::Maven::RegistryUpstream
              .sync_higher_positions(upstream.registry_upstreams)
            upstream.destroy
          end

          if upstream.destroyed?
            ServiceResponse.success(payload: upstream)
          else
            ServiceResponse.error(message: upstream.errors.full_messages)
          end
        end
      end
    end
  end
end
