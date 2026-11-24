# frozen_string_literal: true

module Security
  module DependencyFirewallPolicies
    class MaliciousRule < Rule
      def apply(_package, metadata: {})
        return unless malicious_rule?

        malicious_packages = Array(metadata[:malicious_packages])
        return result(ACTION_ALLOWED) if malicious_packages.empty?

        result(denies_malicious? ? ACTION_DENIED : ACTION_ALLOWED)
      end

      private

      def denies_malicious?
        denied.any? { |entry| entry[:is_malicious] }
      end
    end
  end
end
