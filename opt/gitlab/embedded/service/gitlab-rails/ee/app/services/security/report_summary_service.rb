# frozen_string_literal: true

module Security
  class ReportSummaryService
    include Gitlab::Utils::StrongMemoize

    SCANNED_RESOURCES_LIMIT = 20

    REPORT_TYPES_WITH_SCANNED_RESOURCES = ::Security::ScannedResourcesService::REPORT_TYPES_WITH_SCANNED_RESOURCES

    MAX_SCANNED_RESOURCES_ARTIFACTS_COUNT = 100
    MAX_SCANNED_RESOURCES_ARTIFACTS_SIZE = 20.megabytes

    # @param [Ci::Pipeline] pipeline
    # @param [Hash[Symbol, Array[Symbol]] selection_information keys must be in the set of Enums::Vulnerability.report_types for example: {dast: [:scanned_resources_count, :vulnerabilities_count], container_scanning:[:vulnerabilities_count]}
    def initialize(pipeline, selection_information, current_user:)
      @pipeline = pipeline
      @selection_information = selection_information
      @current_user = current_user
    end

    def execute
      @selection_information.each_with_object({}) do |(report_type, summary_types), response|
        response[report_type] = summary_counts_for_report_type(report_type.to_s, summary_types)
      end
    end

    private

    def summary_counts_for_report_type(report_type, summary_types)
      return unless has_report?(report_type)

      summary_types.each_with_object({}) do |summary_type, response|
        case summary_type
        when :vulnerabilities_count
          response[:vulnerabilities_count] = vulnerability_counts[report_type]
        when :scanned_resources_count
          response[:scanned_resources_count] =
            scanned_resources_limit_error(report_type) || scanned_resources_counts[report_type]
        when :scanned_resources
          response[:scanned_resources] = scanned_resources_limit_error(report_type) || scanned_resources[report_type]
        when :scanned_resources_csv_path
          response[:scanned_resources_csv_path] = csv_path
        when :scans
          response[:scans] = grouped_scans[report_type]
        end
      end
    end

    def scanned_resources_limit_error(report_type)
      return unless REPORT_TYPES_WITH_SCANNED_RESOURCES.include?(report_type)
      return unless Feature.enabled?(:scanned_resources_graphql_limits, @pipeline.project)

      # Each field needs its own error, because GraphQL sets the error's path to the first field that returns it.
      message = scanned_resources_limit_message
      GraphQL::ExecutionError.new(message) if message
    end

    def scanned_resources_limit_message
      strong_memoize(:scanned_resources_limit_message) do
        if scanned_resources_rate_limited?
          'Too many scanned resources requests. Try again later.'
        elsif scanned_resources_artifacts_too_large?
          'Scanned resources are too large to load for this pipeline.'
        end
      end
    end

    # When the DAST and API fuzzing artifacts are too large or too many, or the user is
    # rate limited (see scanned_resources_limit_error), leave those report types out, so
    # asking for another report type in the same query doesn't parse them anyway.
    def report_types_within_limits(summary_type)
      report_types = requested_report_types(summary_type)
      return report_types unless report_types.any? { |report_type| scanned_resources_limit_error(report_type) }

      report_types - REPORT_TYPES_WITH_SCANNED_RESOURCES
    end

    def scanned_resources_rate_limited?
      ::Gitlab::ApplicationRateLimiter.throttled?(:scanned_resources_graphql, scope: { user: @current_user })
    end

    def scanned_resources_artifacts_too_large?
      builds = @pipeline.latest_report_builds_in_self_and_project_descendants(
        ::Ci::JobArtifact.security_reports(file_types: REPORT_TYPES_WITH_SCANNED_RESOURCES)
      ).limit(MAX_SCANNED_RESOURCES_ARTIFACTS_COUNT + 1)
      artifacts = builds.flat_map do |build|
        build.job_artifacts.select { |artifact| REPORT_TYPES_WITH_SCANNED_RESOURCES.include?(artifact.file_type) }
      end

      artifacts.size > MAX_SCANNED_RESOURCES_ARTIFACTS_COUNT ||
        artifacts.sum { |artifact| artifact.size.to_i } > MAX_SCANNED_RESOURCES_ARTIFACTS_SIZE
    end

    def has_report?(report_type)
      grouped_scans[report_type].present?
    end

    def csv_path
      ::Gitlab::Routing.url_helpers.project_security_scanned_resources_path(
        @pipeline.project,
        format: :csv,
        pipeline_id: @pipeline.id)
    end

    def requested_report_types(summary_type)
      @report_types_for_summary_type ||= Gitlab::Utils.multiple_key_invert(@selection_information)
      @report_types_for_summary_type[summary_type].map(&:to_s)
    end

    def scanned_resources
      strong_memoize(:scanned_resources) do
        ::Security::ScannedResourcesService.new(@pipeline, report_types_within_limits(:scanned_resources), SCANNED_RESOURCES_LIMIT).execute
      end
    end

    def vulnerability_counts
      strong_memoize(:vulnerability_counts) do
        ::Security::VulnerabilityCountingService.new(@pipeline, requested_report_types(:vulnerabilities_count)).execute
      end
    end

    def scanned_resources_counts
      strong_memoize(:scanned_resources_counts) do
        ::Security::ScannedResourcesCountingService.new(@pipeline, report_types_within_limits(:scanned_resources_count)).execute
      end
    end

    def grouped_scans
      @grouped_scans ||= @pipeline.security_scans.by_scan_types(@selection_information.keys.map(&:to_sym) & Security::Scan.scan_types.keys.map(&:to_sym)).group_by(&:scan_type)
    end
  end
end
