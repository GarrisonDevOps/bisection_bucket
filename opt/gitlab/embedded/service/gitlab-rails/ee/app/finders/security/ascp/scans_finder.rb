# frozen_string_literal: true

module Security
  module Ascp
    class ScansFinder
      def initialize(project:, params: {})
        @project = project
        @params = params
      end

      def execute
        scans = @project.security_ascp_scans.ordered
        filter_by_scan_type(scans)
      end

      private

      def filter_by_scan_type(scans)
        return scans unless @params[:scan_type].present?

        scans.by_scan_type(@params[:scan_type])
      end
    end
  end
end
