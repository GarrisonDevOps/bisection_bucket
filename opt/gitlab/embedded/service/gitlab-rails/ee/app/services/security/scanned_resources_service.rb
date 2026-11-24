# frozen_string_literal: true

module Security
  # Service for getting the scanned resources for
  # an array of report types within a pipeline
  #
  class ScannedResourcesService
    # Only the DAST parser sets scanned resources, and it parses these report types.
    REPORT_TYPES_WITH_SCANNED_RESOURCES = %w[dast api_fuzzing].freeze

    # @param [Ci::Pipeline] pipeline
    # @param Array[Symbol] report_types Summary report types. Valid values are members of Enums::Vulnerability.report_types
    # @param [Int] The maximum number of scanned resources to return
    def initialize(pipeline, report_types, limit = nil)
      @pipeline = pipeline
      @report_types = report_types
      @limit = limit
    end

    def execute
      report_types_to_parse = @report_types.map(&:to_s) & REPORT_TYPES_WITH_SCANNED_RESOURCES
      return @report_types.index_with { [] } if report_types_to_parse.empty?

      reports = @pipeline&.security_reports(report_types: report_types_to_parse)&.reports || {}
      @report_types.each_with_object({}) do |type, acc|
        scanned_resources = reports[type]&.scanned_resources || []
        scanned_resources = scanned_resources.first(@limit) if @limit
        acc[type] = scanned_resources.map do |resource|
          {
            'request_method' => resource.request_method,
            'url' => resource.request_uri.to_s
          }
        end
      end
    end
  end
end
