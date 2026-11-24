# frozen_string_literal: true

module Vulnerabilities
  class UploadRemediationsWorker
    include ApplicationWorker

    idempotent!
    deduplicate :until_executing, including_scheduled: true
    urgency :low
    data_consistency :delayed
    feature_category :vulnerability_management
    defer_on_database_health_signal :gitlab_sec, [:vulnerability_remediations], 1.minute

    def perform(remediation_diffs_by_id)
      remediation_diffs_by_id.each do |remediation_id, diff_content|
        remediation = Vulnerabilities::Remediation.find_by_id(remediation_id)

        unless remediation
          logger.warn(structured_payload(
            message: 'Remediation not found, skipping upload',
            remediation_id: remediation_id
          ))
          next
        end

        diff_file = ::Gitlab::Ci::Reports::Security::Remediation::DiffFile.new(diff_content)
        remediation.update(file: diff_file)
      rescue StandardError => e
        logger.error(structured_payload(
          message: 'Failed to upload remediation file',
          remediation_id: remediation_id,
          error: e.message
        ))
      end
    end
  end
end
