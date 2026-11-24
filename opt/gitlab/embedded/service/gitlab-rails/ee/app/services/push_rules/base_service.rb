# frozen_string_literal: true

module PushRules
  class BaseService < BaseContainerService
    attr_reader :organization

    def organization_container?
      container.is_a?(::Organizations::Organization)
    end

    private

    def handle_container_type(container)
      super

      @organization = container if container.is_a?(Organizations::Organization)
    end
  end
end
