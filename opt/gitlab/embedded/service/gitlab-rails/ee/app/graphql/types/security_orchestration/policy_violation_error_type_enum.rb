# frozen_string_literal: true

module Types
  module SecurityOrchestration
    class PolicyViolationErrorTypeEnum < BaseEnum
      graphql_name 'PolicyViolationErrorType'

      value 'SCAN_REMOVED',
        value: 'SCAN_REMOVED',
        description: 'Represents mismatch between the scans of the source and target pipelines.'

      value 'ARTIFACTS_MISSING',
        value: 'ARTIFACTS_MISSING',
        description: 'Represents error which occurs when pipeline is misconfigured and does not include ' \
          'necessary artifacts to evaluate a policy.'

      value 'SCAN_NOT_SUCCEEDED',
        value: 'SCAN_NOT_SUCCEEDED',
        description: 'Represents error which occurs when a security scan job did not complete successfully ' \
          '(e.g., was canceled or failed), preventing policy evaluation.'

      value 'SCAN_RESULTS_UNAVAILABLE',
        value: 'SCAN_RESULTS_UNAVAILABLE',
        description: 'Represents error which occurs when the results of a security scan are no longer available ' \
          'because its results expired or were deleted, preventing policy evaluation.'

      value 'TARGET_SCAN_MISSING',
        value: 'TARGET_SCAN_MISSING',
        description: 'Represents error which occurs when the scans enforced by a policy could not be found in the ' \
          'target branch pipelines.'

      value 'TARGET_PIPELINE_MISSING',
        value: 'TARGET_PIPELINE_MISSING',
        description: 'Represents error which occurs when the SBOM reports required by a policy could not be found ' \
          'on the target branch.'

      value 'EVALUATION_SKIPPED',
        value: 'EVALUATION_SKIPPED',
        description: 'Represents error which occurs when a policy could not be evaluated within the specified ' \
          'timeframe, so approvals are required for the policy.'

      value 'PIPELINE_FAILED',
        value: 'PIPELINE_FAILED',
        description: 'Represents error which occurs when a policy could not be evaluated because the latest ' \
          'pipeline failed.'

      value 'UNKNOWN',
        value: 'UNKNOWN',
        description: 'Represents unknown error.'
    end
  end
end
