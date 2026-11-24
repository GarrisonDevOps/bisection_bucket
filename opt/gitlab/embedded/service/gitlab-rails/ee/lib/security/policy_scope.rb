# frozen_string_literal: true

module Security
  class PolicyScope
    MATCH_MODE_ALL = 'all'
    MATCH_MODE_ANY = 'any'
    DEFAULT_MATCH_MODE = MATCH_MODE_ALL
    BUSINESS_IMPACT_TEMPLATE_TYPE = 'business_impact'
    APPLICATION_TEMPLATE_TYPE = 'application'
    BUSINESS_UNIT_TEMPLATE_TYPE = 'business_unit'
    EXPOSURE_TEMPLATE_TYPE = 'exposure'

    SECURITY_ATTRIBUTE_SCOPE_KEYS = {
      business_impact: BUSINESS_IMPACT_TEMPLATE_TYPE,
      application: APPLICATION_TEMPLATE_TYPE,
      business_unit: BUSINESS_UNIT_TEMPLATE_TYPE,
      exposure: EXPOSURE_TEMPLATE_TYPE
    }.freeze

    def initialize(policy_scope)
      @policy_scope = policy_scope || {}
    end

    def match_mode
      policy_scope[:match_mode] || DEFAULT_MATCH_MODE
    end

    def match_mode_any?
      match_mode == MATCH_MODE_ANY
    end

    def compliance_frameworks
      policy_scope[:compliance_frameworks] || []
    end

    def projects
      policy_scope[:projects] || {}
    end

    def groups
      policy_scope[:groups] || {}
    end

    def business_impact
      policy_scope[:business_impact] || {}
    end

    def application
      policy_scope[:application] || {}
    end

    def business_unit
      policy_scope[:business_unit] || {}
    end

    def exposure
      policy_scope[:exposure] || {}
    end

    def has_security_attribute?(scope_key, security_attribute_id)
      includes_security_attribute?(scope_key, security_attribute_id) ||
        excludes_security_attribute?(scope_key, security_attribute_id)
    end

    def references_any_security_attribute?(security_attribute_id)
      SECURITY_ATTRIBUTE_SCOPE_KEYS.each_key.any? do |scope_key|
        has_security_attribute?(scope_key, security_attribute_id)
      end
    end

    private

    attr_reader :policy_scope

    def includes_security_attribute?(scope_key, security_attribute_id)
      scope = policy_scope[scope_key]
      return false unless scope.is_a?(Hash)

      Array.wrap(scope[:including]).any? { |attribute| attribute[:id] == security_attribute_id }
    end

    def excludes_security_attribute?(scope_key, security_attribute_id)
      scope = policy_scope[scope_key]
      return false unless scope.is_a?(Hash)

      Array.wrap(scope[:excluding]).any? { |attribute| attribute[:id] == security_attribute_id }
    end
  end
end
