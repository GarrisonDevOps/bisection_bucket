# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class PipelineAuditor
      include Gitlab::Utils::StrongMemoize

      def initialize(pipeline:)
        @pipeline = pipeline
      end

      def audit
        return unless pipeline
        return unless security_orchestration_policy_configurations.present?

        security_orchestration_policy_configurations.each do |policy_configuration|
          skipped_policies = skipped_policies(policy_configuration)

          next if skipped_policies.blank?

          ::Gitlab::Audit::Auditor.audit(audit_context(policy_configuration, skipped_policies))
        end
      end

      private

      attr_reader :pipeline

      def event_name
        raise NoMethodError, "#{self.class} must implement the method #{__method__}"
      end

      def event_message
        raise NoMethodError, "#{self.class} must implement the method #{__method__}"
      end

      def audit_context(policy_configuration, skipped_policies)
        {
          name: event_name,
          author: pipeline_author,
          scope: policy_configuration.security_policy_management_project,
          target: pipeline,
          target_details: pipeline.id.to_s,
          message: event_message,
          additional_details: additional_details(skipped_policies)
        }
      end

      def additional_details(skipped_policies)
        additional_details_base.merge({ skipped_policies: skipped_policies })
      end

      def additional_details_base
        {
          commit_sha: pipeline.sha,
          merge_request_title: merge_request&.title,
          merge_request_id: merge_request&.id,
          merge_request_iid: merge_request&.iid,
          source_branch: merge_request&.source_branch,
          target_branch: merge_request&.target_branch,
          project_id: project.id,
          project_name: project.name,
          project_full_path: project.full_path
        }.compact
      end
      strong_memoize_attr :additional_details_base

      def skipped_policies(policy_configuration)
        pipeline_execution_policies, scan_execution_policies = active_execution_policies(policy_configuration)

        skipped_seps = format_skipped_policies(scan_execution_policies, 'scan_execution_policy')
        skipped_peps = format_skipped_policies(pipeline_execution_policies, 'pipeline_execution_policy')

        skipped_seps + skipped_peps
      end

      def active_execution_policies(policy_configuration)
        active_seps_for_policy = if target_branch_ref
                                   policy_configuration.active_scan_execution_policy_names(target_branch_ref, project)
                                 else
                                   []
                                 end

        active_peps_for_policy = policy_configuration.active_pipeline_execution_policy_names(project) || []

        [active_peps_for_policy, active_seps_for_policy]
      end

      def format_skipped_policies(policies, type)
        policies.map { |name| { name: name, policy_type: type } }
      end

      def security_orchestration_policy_configurations
        project&.all_security_orchestration_policy_configurations
      end
      strong_memoize_attr :security_orchestration_policy_configurations

      def project
        pipeline.project
      end
      strong_memoize_attr :project

      def merge_request
        pipeline.all_merge_requests.first
      end
      strong_memoize_attr :merge_request

      def target_branch_ref
        merge_request&.target_branch_ref
      end
      strong_memoize_attr :target_branch_ref

      def pipeline_author
        pipeline.user || Gitlab::Audit::DeletedAuthor.new(
          id: Gitlab::Audit::NullAuthor::UNKNOWN_USER_AUTHOR_ID, name: 'Unknown User'
        )
      end
      strong_memoize_attr :pipeline_author
    end
  end
end
