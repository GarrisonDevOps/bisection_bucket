# frozen_string_literal: true

module Security
  module ScanExecutionPolicies
    class ScanSettings
      def initialize(scan_settings)
        @scan_settings = scan_settings || {}
      end

      def ignore_default_before_after_script
        scan_settings[:ignore_default_before_after_script]
      end

      private

      attr_reader :scan_settings
    end
  end
end
