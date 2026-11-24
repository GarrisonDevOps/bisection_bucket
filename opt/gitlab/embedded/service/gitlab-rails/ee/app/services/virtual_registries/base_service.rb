# frozen_string_literal: true

module VirtualRegistries
  class BaseService < ::BaseContainerService
    alias_method :registry, :container

    NETWORK_TIMEOUT = 5

    BASE_ERRORS = {
      path_not_present: ServiceResponse.error(message: 'Path not present', reason: :path_not_present)
    }.freeze

    def initialize(registry:, current_user: nil, params: {})
      super(container: registry, current_user: current_user, params: params)
    end
  end
end
