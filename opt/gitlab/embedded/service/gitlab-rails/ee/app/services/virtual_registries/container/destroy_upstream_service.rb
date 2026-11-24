# frozen_string_literal: true

module VirtualRegistries
  module Container
    class DestroyUpstreamService < BaseContainerService
      alias_method :upstream, :container

      def initialize(upstream:, current_user:)
        super(container: upstream, current_user: current_user)
      end

      def execute
        unless ::VirtualRegistries::Container.virtual_registry_available?(upstream.group, current_user,
          :destroy_virtual_registry)
          return ServiceResponse.error(
            message: s_('VirtualRegistry|Container virtual registry not available'), reason: :unavailable
          )
        end

        upstream.transaction do
          ::VirtualRegistries::Container::RegistryUpstream
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
