# frozen_string_literal: true

module VirtualRegistries
  class CreateRegistryService < ::BaseGroupService
    def execute
      return ServiceResponse.error(message: unavailable_message, reason: :unavailable) unless registry_available?

      registry = registry_class.build(params.merge(group: group))

      if registry.save
        ServiceResponse.success(payload: registry)
      else
        ServiceResponse.error(message: registry.errors.full_messages)
      end
    end

    private

    def registry_available?
      availability_class.virtual_registry_available?(group, current_user)
    end

    def unavailable_message
      raise NotImplementedError, "Subclasses must implement #unavailable_message"
    end

    def registry_class
      raise NotImplementedError, "Subclasses must implement #registry_class"
    end

    def availability_class
      raise NotImplementedError, "Subclasses must implement #availability_class"
    end
  end
end
