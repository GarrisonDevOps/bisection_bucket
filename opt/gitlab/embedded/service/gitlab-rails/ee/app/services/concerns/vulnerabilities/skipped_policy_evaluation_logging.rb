# frozen_string_literal: true

module Vulnerabilities
  # Logs when a vulnerability management policy service returns early because
  # the project has no linked policy of its type.
  #
  # Including classes must respond to `project`, `pipeline` and `vulnerability_ids`.
  module SkippedPolicyEvaluationLogging
    include Gitlab::Loggable

    SKIPPED_POLICY_EVALUATION_MESSAGE = 'Skipping vulnerability management policy evaluation: no linked policy'

    private

    def log_skipped_policy_evaluation(policy_action)
      return if vulnerability_ids.blank?
      return unless ::Security::PolicyAvailability.any_available?(project)
      return unless policy_configuration_linked?

      Gitlab::AppJsonLogger.info(
        build_structured_payload_labkit(
          Labkit::Fields::LOG_MESSAGE => SKIPPED_POLICY_EVALUATION_MESSAGE,
          Labkit::Fields::GL_PROJECT_ID => project.id,
          Labkit::Fields::GL_PIPELINE_ID => pipeline.id,
          policy_action: policy_action,
          vulnerabilities_count: vulnerability_ids.size
        )
      )
    end

    # Most projects never link a security policy project, so a missing policy is only an anomaly when
    # a configuration is linked to the project or one of its parent groups. Validity does not matter:
    # an invalid policy.yml is the failure mode this log has to surface, so invalid configurations count
    # and policy.yml is never read.
    def policy_configuration_linked?
      project.security_orchestration_policy_configuration.present? ||
        project.all_inherited_security_orchestration_policy_configurations(include_invalid: true).any?
    end
  end
end
