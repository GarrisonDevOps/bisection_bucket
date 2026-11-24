# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class ScannerConfig
      attr_reader :type, :vulnerability_attributes, :severity_levels,
        :vulnerabilities_allowed, :vulnerability_states, :is_malicious, :dependency_change, :dependency_type

      def initialize(
        type:, vulnerability_attributes: nil, severity_levels: nil,
        vulnerabilities_allowed: nil, vulnerability_states: nil, is_malicious: false,
        dependency_change: nil, dependency_type: nil)
        @type = type
        @vulnerability_attributes = vulnerability_attributes
        @severity_levels = severity_levels
        @vulnerabilities_allowed = vulnerabilities_allowed
        @vulnerability_states = vulnerability_states
        @is_malicious = is_malicious
        @dependency_change = dependency_change
        @dependency_type = dependency_type
      end

      def to_h
        { type: type, vulnerability_attributes: vulnerability_attributes }.tap do |hash|
          hash[:severity_levels] = severity_levels if severity_levels
          hash[:vulnerabilities_allowed] = vulnerabilities_allowed if vulnerabilities_allowed
          hash[:vulnerability_states] = vulnerability_states if vulnerability_states
          hash[:is_malicious] = is_malicious if is_malicious
          hash[:dependency_change] = dependency_change if dependency_change
          hash[:dependency_type] = dependency_type if dependency_type
        end
      end
    end
  end
end
