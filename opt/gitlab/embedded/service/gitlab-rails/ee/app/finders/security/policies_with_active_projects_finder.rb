# frozen_string_literal: true

module Security
  class PoliciesWithActiveProjectsFinder
    def initialize(config_ids:)
      @config_ids = config_ids
    end

    def execute
      Security::Policy.policy_identifiers_with_active_projects(@config_ids)
    end
  end
end
