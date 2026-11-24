# frozen_string_literal: true

module Ci
  class CompareLicenseScanningReportsService < ::Ci::CompareReportsBaseService
    include ::Gitlab::Utils::StrongMemoize

    def comparer_class
      Gitlab::Ci::Reports::LicenseScanning::ReportsComparer
    end

    def serializer_class
      ::LicenseCompliance::ComparerSerializer
    end

    def get_report(pipeline)
      # Scan as the viewing user so artifacts they cannot read are filtered out.
      # A nil user is treated as a guest (public artifacts only), never unscoped.
      ::SCA::LicenseCompliance.new(pipeline&.project || project, pipeline, merge_request&.target_branch, current_user,
        self_and_project_descendants: include_child_pipeline_sboms?)
    end

    private

    attr_reader :comparer_entity

    def merge_request
      project.merge_requests.find_by_id(params[:id])
    end
    strong_memoize_attr :merge_request

    def build_comparer(base_report, head_report)
      @comparer_entity = comparer_class.new(base_report, head_report)
    end

    def approval_required
      return false unless params[:id]

      return false unless merge_request

      (merge_request.approval_rules.license_compliance.any? ||
        merge_request.approval_rules.scan_finding.any?) && has_denied_licenses?
    end
    strong_memoize_attr :approval_required

    def has_denied_licenses?
      licenses = comparer_entity.new_licenses

      return false if licenses.nil? || licenses.empty?

      licenses.any? do |l|
        l.approval_status == 'denied'
      end
    end
    strong_memoize_attr :has_denied_licenses?

    def serializer_params
      {
        project: project,
        current_user: current_user,
        approval_required: approval_required,
        has_denied_licenses: has_denied_licenses?
      }
    end

    def include_child_pipeline_sboms?
      ::Feature.enabled?(:include_child_pipeline_sboms_in_pipeline_licenses, project)
    end

    # The flag changes the compared data without touching either pipeline, so it must invalidate the cache.
    def key(base_pipeline, head_pipeline)
      super + [project.software_license_policies.cache_key, include_child_pipeline_sboms?]
    end
  end
end
