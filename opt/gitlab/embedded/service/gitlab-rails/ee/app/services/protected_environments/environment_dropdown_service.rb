# frozen_string_literal: true

module ProtectedEnvironments
  class EnvironmentDropdownService
    attr_reader :container

    def self.human_access_levels
      ::ProtectedEnvironments::DeployAccessLevel::HUMAN_ACCESS_LEVELS
    end

    def initialize(container)
      @container = container
    end

    def roles_hash
      { roles: roles }
    end

    def roles
      filtered_human_access_levels.map do |id, text|
        { id: id, text: text, before_divider: true }
      end
    end

    private

    def filtered_human_access_levels
      levels = self.class.human_access_levels
      levels = levels.except(Gitlab::Access::DEVELOPER) if container.is_a?(::Group)
      levels
    end
  end
end
