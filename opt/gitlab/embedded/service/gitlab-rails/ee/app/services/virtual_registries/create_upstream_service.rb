# frozen_string_literal: true

module VirtualRegistries
  class CreateUpstreamService < ::VirtualRegistries::BaseService
    ERRORS = BASE_ERRORS.merge(
      unauthorized: ServiceResponse.error(message: 'Unauthorized', reason: :unauthorized)
    )

    def execute
      return ERRORS[:unauthorized] unless allowed?

      new_registry_upstream = registry.upstreams.build(params.merge(group: registry.group))

      if new_registry_upstream.save
        ServiceResponse.success(payload: new_registry_upstream)
      else
        ServiceResponse.error(payload: new_registry_upstream, message: new_registry_upstream.errors.full_messages,
          reason: :invalid)
      end
    end

    private

    def allowed?
      return false unless current_user # anonymous users can't access virtual registries

      can?(current_user, :create_virtual_registry, registry)
    end
  end
end
