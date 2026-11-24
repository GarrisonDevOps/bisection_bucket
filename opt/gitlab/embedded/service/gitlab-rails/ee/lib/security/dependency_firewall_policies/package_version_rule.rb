# frozen_string_literal: true

module Security
  module DependencyFirewallPolicies
    class PackageVersionRule < Rule
      def apply(package, **)
        return unless package_version_rule?

        entry = denied.find { |e| e[:name] == package[:name] && e[:version] == package[:version] }
        return result(ACTION_ALLOWED) unless entry

        result(ACTION_DENIED, details: ({ reason: entry[:reason] } if entry[:reason].present?))
      end
    end
  end
end
