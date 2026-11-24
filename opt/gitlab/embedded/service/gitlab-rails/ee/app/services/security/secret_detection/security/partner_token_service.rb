# frozen_string_literal: true

module Security
  module SecretDetection
    module Security
      class PartnerTokenService < PartnerTokenServiceBase
        class << self
          def finding_type
            :security
          end

          def token_status_model
            ::Security::FindingTokenStatus
          end

          def unique_by_column
            :security_finding_id
          end

          def save_result(finding, result)
            related_findings = get_related_security_findings(finding)

            # Batch save all security findings
            super(related_findings, result)

            # Batch save vulnerability findings
            save_vulnerability_findings(related_findings, result)
          end

          private

          def save_vulnerability_findings(security_findings, result)
            vuln_findings = security_findings.filter_map { |sf| sf.vulnerability&.finding }.uniq
            Vulnerabilities::PartnerTokenService.save_result(vuln_findings, result) if vuln_findings.any?
          end

          def get_related_security_findings(finding)
            partition = [finding.partition_number].compact
            ::Security::Finding
              .by_project_id_and_uuid(finding.project_id, partition, finding.uuid)
              .with_vulnerability
          end
        end
      end
    end
  end
end
