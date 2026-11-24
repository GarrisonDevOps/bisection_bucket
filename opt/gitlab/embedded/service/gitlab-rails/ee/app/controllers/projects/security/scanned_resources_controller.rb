# frozen_string_literal: true

module Projects
  module Security
    class ScannedResourcesController < ::Projects::ApplicationController
      include SecurityAndCompliancePermissions

      # Parsing happens in the web request, so cap how much a single CSV download can parse.
      MAX_DAST_ARTIFACTS_COUNT = 100
      MAX_DAST_ARTIFACTS_SIZE = 20.megabytes

      before_action :authorize_read_vulnerability!
      before_action :check_csv_download_rate_limit!
      before_action :scanned_resources

      feature_category :dynamic_application_security_testing
      urgency :low

      def index
        respond_to do |format|
          format.csv do
            send_data(
              render_csv,
              type: 'text/csv; charset=utf-8'
            )
          end
        end
      end

      private

      def scanned_resources
        pipeline = project.all_pipelines.find(pipeline_id)
        return render_dast_reports_too_large if dast_reports_too_large?(pipeline)

        @scanned_resources = pipeline.security_reports(report_types: %w[dast]).reports['dast']&.scanned_resources

        return if @scanned_resources

        render_404
      end

      def check_csv_download_rate_limit!
        return unless limits_enabled?

        check_rate_limit!(:scanned_resources_csv_download, scope: { user: current_user })
      end

      def dast_reports_too_large?(pipeline)
        return false unless limits_enabled?

        builds = pipeline.latest_report_builds_in_self_and_project_descendants(
          ::Ci::JobArtifact.security_reports(file_types: %w[dast])
        ).limit(MAX_DAST_ARTIFACTS_COUNT + 1)
        artifacts = builds.flat_map { |build| build.job_artifacts.select(&:dast?) }

        artifacts.size > MAX_DAST_ARTIFACTS_COUNT ||
          artifacts.sum { |artifact| artifact.size.to_i } > MAX_DAST_ARTIFACTS_SIZE
      end

      def render_dast_reports_too_large
        render plain: _('The DAST reports for this pipeline are too large to export as CSV. ' \
          'Download the DAST report artifact instead.'), status: :unprocessable_entity
      end

      def limits_enabled?
        Feature.enabled?(:scanned_resources_csv_limits, project)
      end

      def render_csv
        CsvBuilder::SingleBatch.new(
          @scanned_resources,
          {
            Method: 'request_method',
            Scheme: 'url_scheme',
            Host: 'url_host',
            Port: 'url_port',
            Path: 'url_path',
            'Query String': 'url_query'
          }
        ).render
      end

      def pipeline_id
        params.require(:pipeline_id)
      end

      def authorize_read_vulnerability!
        return if can?(current_user, :read_security_resource, project)

        render_404
      end
    end
  end
end
