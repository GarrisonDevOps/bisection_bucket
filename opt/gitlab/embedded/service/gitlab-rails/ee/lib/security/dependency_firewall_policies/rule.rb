# frozen_string_literal: true

module Security
  module DependencyFirewallPolicies
    class Rule
      ACTION_ALLOWED = :allowed
      ACTION_DENIED = :denied
      ACTION_WARNED = :warned

      REASON_EXCEPTION = :exception
      REASON_EVALUATION = :evaluation
      REASON_NO_MATCHES = :no_matches
      # Nothing was evaluated, as distinct from REASON_NO_MATCHES, where rules ran and none matched.
      REASON_NO_POLICIES = :no_policies
      REASON_NO_RULES = :no_rules

      NON_EVALUATION_REASONS = [REASON_NO_POLICIES, REASON_NO_RULES].freeze

      def self.non_evaluation_reason?(reason)
        NON_EVALUATION_REASONS.include?(reason)
      end

      def self.by_type(rule_hash)
        case rule_hash[:type]
        when "license"
          Security::DependencyFirewallPolicies::LicenseRule.new(rule_hash)
        when "malicious"
          Security::DependencyFirewallPolicies::MaliciousRule.new(rule_hash)
        when "risk_severity"
          Security::DependencyFirewallPolicies::RiskSeverityRule.new(rule_hash)
        when "package_version"
          Security::DependencyFirewallPolicies::PackageVersionRule.new(rule_hash)
        else
          Security::DependencyFirewallPolicies::Rule.new(rule_hash)
        end
      end

      def initialize(rule_hash)
        @rule = rule_hash || {}
      end

      def license_rule?
        type == "license"
      end

      def malicious_rule?
        type == "malicious"
      end

      def risk_severity_rule?
        type == "risk_severity"
      end

      def package_version_rule?
        type == "package_version"
      end

      def purl_excepted?(package)
        purl_with_version = purl_string(package)
        purl_without_version = purl_string(package, include_version: false)

        package_purl = proc do |e_purl|
          (e_purl.split('/').last.include?('@') ? purl_with_version : purl_without_version).eql?(e_purl)
        end

        exception_purls.any?(package_purl)
      end

      def type
        rule[:type]
      end

      # Advisories this rule actually weighs: its id-based exceptions removed. Shared by the
      # risk severity rule and the prevented-entities ledger's severity attribution.
      def non_excepted_vulnerabilities(vulnerabilities)
        return vulnerabilities if exception_ids.empty?

        vulnerabilities.reject { |vuln| exception_ids.include?(vuln[:id]) }
      end

      # The persisted dependency_firewall_policy_rules.id, when threaded in by
      # DependencyFirewallPolicy#rules. Nil for rules built directly from raw YAML.
      def rule_id
        rule[:rule_id]
      end

      # Excludes the internal rule_id so it does not leak into serialized rule content (e.g. audit
      # event additional_details, which serializes matched_rule.to_h). rule_id is exposed only via
      # the reader above for activity-stat attribution.
      def to_h
        rule.except(:rule_id)
      end

      def evaluate(package, metadata: {})
        return result(ACTION_ALLOWED, REASON_EXCEPTION) if purl_excepted?(package)

        apply(package, metadata: metadata)
      end

      def apply(_package, metadata: {})
        # no-op, override in each subclass
      end

      private

      attr_reader :rule

      # `details` carries evaluation output that cannot be re-derived from rule config, such as an
      # observed per-severity tally. Merged only when present, so rules that produce none return
      # the same two-key hash they always have.
      def result(action, reason = REASON_EVALUATION, details: nil)
        result = { action: action, reason: reason }
        result[:details] = details if details
        result
      end

      def exception_purls
        exceptions.filter_map { |exception| exception[:purl] }
      end

      def exception_ids
        @exception_ids ||= exceptions.filter_map { |exception| exception[:id] }.to_set
      end

      def purl_string(package, include_version: true)
        base = "pkg:#{package[:purl_type]}/#{package[:name]}"
        return base if package[:version].blank? || !include_version

        "#{base}@#{package[:version]}"
      end

      def denied
        rule[:denied] || []
      end

      def allowed
        rule[:allowed] || []
      end

      def exceptions
        rule[:exceptions] || []
      end
    end
  end
end
