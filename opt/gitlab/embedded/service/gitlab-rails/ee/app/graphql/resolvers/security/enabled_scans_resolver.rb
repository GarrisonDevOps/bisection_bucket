# frozen_string_literal: true

module Resolvers
  module Security
    class EnabledScansResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      type ::Types::Security::EnabledScansType, null: false
      authorize :read_security_resource

      def resolve(...)
        enabled_scans = ::Security::Scan.scan_types.transform_values { false }
        scans_in_pipeline.each { |scan_type| enabled_scans[scan_type] = true }
        enabled_scans.merge({ ready: ready })
      end

      private

      def ready
        ::Security::Scan.results_ready?(object)
      end

      def scans_in_pipeline
        model.by_pipeline_ids(pipeline_ids).distinct_scan_types
      end

      def pipeline_ids
        ids = object.self_and_project_descendants.pluck_primary_key
        # Agentic analyzers (for example the business logic security scan) publish
        # their reports on a separate duo_workflow workload pipeline. This gates the
        # scan types the MR security widget shows; the widget compares against that
        # pipeline, so it must count here or the widget picks the wrong scan mode.
        # No-op unless ::Security::AgenticAnalyzer.enabled? for the project.
        ids |= ::Security::AgenticAnalyzer.scan_pipeline_ids_for_pipeline(object)

        # Include scans from related pipelines (for example, the branch
        # pipeline for the same sha) so the security widget renders report
        # types that merge request approval policies and the security policy
        # pipeline merge check already evaluate.
        # See https://gitlab.com/gitlab-org/gitlab/-/work_items/599102.
        ids | ::Security::RelatedPipelinesFinder.cached_ci_and_security_orchestration_pipeline_ids(object)
      end

      def model
        ::Security::Scan
      end
    end
  end
end
