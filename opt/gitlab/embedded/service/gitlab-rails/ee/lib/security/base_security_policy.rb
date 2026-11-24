# frozen_string_literal: true

module Security
  class BaseSecurityPolicy
    def initialize(policy_record)
      @policy_record = policy_record
    end

    def name
      policy_record.name
    end

    def description
      policy_record.description
    end

    def enabled
      policy_record.enabled
    end

    def policy_scope
      Security::PolicyScope.new(policy_record.scope.deep_symbolize_keys || {})
    end

    private

    attr_reader :policy_record
  end
end
