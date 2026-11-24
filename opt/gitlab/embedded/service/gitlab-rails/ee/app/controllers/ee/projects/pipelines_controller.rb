# frozen_string_literal: true

module EE
  module Projects
    module PipelinesController
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      prepended do
        include GovernUsageProjectTracking

        before_action :authorize_read_licenses!, only: [:licenses, :license_count]

        before_action only: [:charts] do
          push_licensed_feature(:ci_job_analytics_for_projects, project)
        end

        before_action only: [:show, :security] do
          push_frontend_feature_flag(:vulnerability_report_latest_mr, project)

          if ::Feature.enabled?(:pipeline_security_ai_vr, project)
            push_frontend_ability(
              ability: :resolve_vulnerability_with_ai,
              resource: project,
              user: current_user
            )
          end
        end

        feature_category :software_composition_analysis, [:licenses, :license_count]
        feature_category :vulnerability_management, [:security]
        feature_category :code_quality, [:codequality_report]

        urgency :low, [:codequality_report, :licenses, :security, :license_count]
        track_govern_activity 'pipeline_security', :security,
          conditions: -> { pipeline.expose_security_dashboard? }
      end

      def security
        if pipeline.expose_security_dashboard?
          render_show
        else
          redirect_to pipeline_path(pipeline)
        end
      end

      def licenses
        scanner = ::Gitlab::LicenseScanning.scanner_for_pipeline(project, pipeline,
          self_and_project_descendants: include_child_pipeline_sboms?)
        return access_to_licenses_denied! unless scanner.has_data?

        respond_to do |format|
          format.html do
            render_show
          end
          format.json do
            render status: :ok, json: LicenseScanningReportsSerializer.new.represent(
              project.license_compliance(pipeline, current_user,
                self_and_project_descendants: include_child_pipeline_sboms?).find_policies(detected_only: true)
            )
          end
        end
      end

      def license_count
        scanner = ::Gitlab::LicenseScanning.scanner_for_pipeline(project, pipeline, current_user,
          self_and_project_descendants: include_child_pipeline_sboms?)
        return access_to_licenses_denied! unless scanner.has_data?

        count = Rails.cache.fetch(license_count_cache_key, expires_in: 7.days) do
          scanner.report.licenses.count
        end

        render status: :ok, json: { license_count: count }
      end

      def codequality_report
        render_show
      end

      private

      def license_count_cache_key
        unless include_child_pipeline_sboms?
          return ['license_count', project.cache_key_with_version, pipeline.cache_key_with_version, current_user.id]
        end

        # Keyed on the hierarchy's SBOM builds, not pipeline timestamps, so it changes only
        # when a (child) pipeline adds or replaces an SBOM, not on every pipeline update.
        ['license_count', project.cache_key_with_version, pipeline.id,
          pipeline.sbom_report_build_ids_in_self_and_project_descendants, current_user.id]
      end

      def include_child_pipeline_sboms?
        ::Feature.enabled?(:include_child_pipeline_sboms_in_pipeline_licenses, project)
      end

      # This overrides the default implementation
      # because this controller chose to respond with a 302 instead of a 404
      def authorize_read_licenses!
        access_to_licenses_denied! unless can?(current_user, :read_licenses, project)
      end

      def access_to_licenses_denied!
        respond_to do |format|
          format.html { redirect_to pipeline_path(pipeline) }
          format.json { head :not_found }
        end
      end
    end
  end
end
