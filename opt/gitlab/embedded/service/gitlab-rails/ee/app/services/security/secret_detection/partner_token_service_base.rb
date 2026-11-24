# frozen_string_literal: true

module Security
  module SecretDetection
    class PartnerTokenServiceBase
      extend Gitlab::InternalEventsTracking

      class << self
        def process_finding_async(findings, project)
          partner_findings = findings.select { |finding| eligible_partner_finding?(finding) }
          return if partner_findings.empty?

          # Batch schedule with context
          ::Security::SecretDetection::PartnerTokenVerificationWorker.bulk_perform_async_with_contexts(
            partner_findings,
            arguments_proc: ->(finding) { [finding.id, finding_type] },
            context_proc: ->(_finding) { { project: project } }
          )
        end

        def process_partner_finding(finding)
          return unless eligible_partner_finding?(finding)

          client = PartnerTokensClient.new(finding)
          return unless client.valid_config?
          return if client.rate_limited?

          result = client.verify_token
          save_result(finding, result)
        end

        def save_result(findings, result)
          findings = Array(findings)
          return if findings.empty?

          save_to_database(findings, result.status, result.metadata[:verified_at])
        end

        def partner_token?(token_type)
          PartnerTokens::Registry.partner_for(token_type).present?
        end

        def eligible_partner_finding?(finding)
          return false unless partner_token?(finding.token_type)

          ValiditySupport.state(
            token_type: finding.token_type,
            source: Scanners.target_for_finding(finding)
          ) == :supported
        end

        # Abstract methods - override in subclasses
        def finding_type
          raise NotImplementedError, "#{name} must implement .finding_type"
        end

        def token_status_model
          raise NotImplementedError, "#{name} must implement .token_status_model"
        end

        def unique_by_column
          raise NotImplementedError, "#{name} must implement .unique_by_column"
        end

        private

        def save_to_database(findings, status, verified_at)
          attributes = findings.map { |finding| build_attributes(finding, status, verified_at) }

          token_status_model.upsert_all(
            attributes,
            unique_by: unique_by_column,
            update_only: [:status, :last_verified_at]
          )

          track_token_verifications(findings, status)
        end

        def build_attributes(finding, status, verified_at)
          {
            unique_by_column => finding.id,
            project_id: finding.project_id,
            status: status,
            last_verified_at: verified_at
          }
        end

        def track_token_verifications(findings, status)
          findings.each do |finding|
            track_internal_event(
              'secret_detection_token_verified',
              project: finding.project,
              namespace: finding.project&.namespace,
              additional_properties: {
                label: finding.token_type,
                property: status.to_s
              }
            )
          end
        end
      end
    end
  end
end
