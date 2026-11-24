# frozen_string_literal: true

module Security
  module ScanProfiles
    class PipelineEligibilityService
      include Gitlab::Utils::StrongMemoize

      def initialize(project:, ref:, pipeline_source:)
        @project = project
        @ref = ref
        @pipeline_source = pipeline_source
      end

      def eligible?
        applicable_profiles_triggers.exists?
      end
      strong_memoize_attr :eligible?

      def applicable_profiles_triggers
        @applicable_profiles_triggers ||= build_applicable_triggers
      end

      def merge_train_pipeline?
        merge_request_pipeline? && ::MergeRequest.merge_train_ref?(ref)
      end

      private

      attr_reader :project, :ref, :pipeline_source

      def build_applicable_triggers
        return ::Security::ScanProfileTrigger.none unless scan_profiles_allowed?

        triggers =
          if merge_request_pipeline?
            project.security_scan_profile_triggers.merge_request_pipeline
          elsif default_branch_pipeline?
            project.security_scan_profile_triggers.default_branch_pipeline
          else
            ::Security::ScanProfileTrigger.none
          end

        # Flow-backed scan types (Business Logic) run as a Duo flow, not as injected CI jobs.
        triggers.with_not_deleted_profile.merge(::Security::ScanProfile.not_flow_backed)
          .with_ci_variables_associations
      end

      def scan_profiles_allowed?
        project.present? &&
          project.licensed_feature_available?(:security_scan_profiles)
      end

      def merge_request_pipeline?
        pipeline_source&.to_sym == :merge_request_event
      end

      def default_branch_pipeline?
        ref.present? && ::Gitlab::Git.ref_name(ref) == project.default_branch_or_main
      end
    end
  end
end
