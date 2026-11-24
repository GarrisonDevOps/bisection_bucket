# frozen_string_literal: true

module VirtualRegistries
  class DestroyRegistryUpstreamService < ::BaseContainerService
    alias_method :registry_upstream, :container

    def initialize(registry_upstream:, current_user: nil, params: {})
      super(container: registry_upstream, current_user: current_user, params: params)
    end

    def execute
      return ServiceResponse.error(message: 'Unauthorized', reason: :unavailable) unless available?

      registry_upstream.transaction do
        registry_upstream.sync_higher_positions
        registry_upstream.destroy
      end

      if registry_upstream.destroyed?
        ServiceResponse.success(payload: registry_upstream)
      else
        ServiceResponse.error(message: registry_upstream.errors.full_messages)
      end
    end

    private

    def available?
      raise NotImplementedError, "#{self} does not implement #{__method__}"
    end
  end
end
