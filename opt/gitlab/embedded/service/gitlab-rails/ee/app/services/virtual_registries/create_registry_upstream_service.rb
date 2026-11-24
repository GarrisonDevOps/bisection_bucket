# frozen_string_literal: true

module VirtualRegistries
  class CreateRegistryUpstreamService < ::VirtualRegistries::BaseService
    def execute
      return ServiceResponse.error(message: 'Unauthorized', reason: :unavailable) unless available?

      unless registry.group.id == params[:upstream].group.id
        return ServiceResponse.error(message: 'Not found', reason: :unavailable)
      end

      registry_upstream = registry_upstream_class.build(params.merge(registry: registry, group: registry.group))

      if registry_upstream.save
        ServiceResponse.success(payload: registry_upstream)
      else
        ServiceResponse.error(message: registry_upstream.errors.full_messages)
      end
    end

    private

    def registry_upstream_class
      raise NotImplementedError, "#{self} does not implement #{__method__}"
    end

    def available?
      raise NotImplementedError, "#{self} does not implement #{__method__}"
    end
  end
end
