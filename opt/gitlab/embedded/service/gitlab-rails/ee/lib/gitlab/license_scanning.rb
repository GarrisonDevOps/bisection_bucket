# frozen_string_literal: true

module Gitlab
  module LicenseScanning
    # Sentinel for internal/system callers (ingestion, policy evaluation, dashboards)
    # that must read every sbom artifact. A real user - or nil for a guest - is
    # authorization-scoped to the artifacts that viewer may read.
    UNSCOPED = :unscoped

    def self.scanner_for_project(project, ref = project.default_branch)
      sbom_pipeline = ::Gitlab::LicenseScanning::SbomScanner.latest_pipeline(project, ref)

      ::Gitlab::LicenseScanning::SbomScanner.new(project, sbom_pipeline)
    end

    def self.scanner_for_pipeline(project, pipeline, user = UNSCOPED, self_and_project_descendants: false)
      ::Gitlab::LicenseScanning::SbomScanner.new(project, pipeline, user,
        self_and_project_descendants: self_and_project_descendants)
    end
  end
end
