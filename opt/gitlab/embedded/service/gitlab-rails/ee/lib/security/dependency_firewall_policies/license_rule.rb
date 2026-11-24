# frozen_string_literal: true

module Security
  module DependencyFirewallPolicies
    class LicenseRule < Rule
      def apply(_package, metadata: {})
        return unless license_rule?

        licenses = Array(metadata[:licenses])
        return result(ACTION_ALLOWED) if licenses.empty?

        return result(ACTION_DENIED)  if licenses_denied?(licenses)
        return result(ACTION_ALLOWED) if licenses_allowed?(licenses)

        # if this is a denial rule and licenses did not match, allow
        # if this is an allowed rule and licenses did not match, block
        result(denied.present? ? ACTION_ALLOWED : ACTION_DENIED)
      end

      def denied_names
        denied.filter_map { |license| license[:name] }
      end

      private

      def licenses_denied?(licenses)
        denied_names = denied.map { |license| license[:name] } # rubocop:disable Rails/Pluck -- Not a ActiveRecord object

        return false if denied_names.empty?

        # Return true if any license is in the denied list
        (denied_names & licenses).any?
      end

      def licenses_allowed?(licenses)
        allowed_names = allowed.map { |license| license[:name] } # rubocop:disable Rails/Pluck -- Not a ActiveRecord object

        return false if allowed_names.empty?

        # Return true if all licenses are in the allowed list
        (licenses - allowed_names).empty?
      end
    end
  end
end
