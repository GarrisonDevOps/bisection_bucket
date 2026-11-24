# frozen_string_literal: true

module Security
  module ScanExecutionPolicies
    class Action
      def initialize(action)
        @action = action || {}
      end

      def scan
        action[:scan]
      end

      def scanner_profile
        action[:scanner_profile]
      end

      def site_profile
        action[:site_profile]
      end

      def variables
        action[:variables] || {}
      end

      def tags
        action[:tags] || []
      end

      def template
        action[:template]
      end

      def scan_settings
        Security::ScanExecutionPolicies::ScanSettings.new(action[:scan_settings] || {})
      end

      private

      attr_reader :action
    end
  end
end
