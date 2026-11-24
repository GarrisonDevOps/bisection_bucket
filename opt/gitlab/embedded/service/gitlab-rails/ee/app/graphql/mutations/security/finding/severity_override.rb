# frozen_string_literal: true

module Mutations
  module Security
    module Finding
      class SeverityOverride < BaseMutation
        graphql_name 'SecurityFindingSeverityOverride'

        authorize :admin_vulnerability

        field :security_finding,
          ::Types::PipelineSecurityReportFindingType,
          null: true,
          description: 'Finding of which the severity was modified.'

        argument :uuid,
          GraphQL::Types::String,
          required: true,
          description: 'UUID of the finding to modify.'

        argument :severity, Types::VulnerabilitySeverityEnum,
          required: true,
          description: 'New severity value for the finding.'

        def resolve(uuid:, severity:)
          Gitlab::QueryLimiting.disable!('https://gitlab.com/gitlab-org/gitlab/-/issues/584029')
          security_finding = authorized_find!(uuid: uuid)
          unless Feature.disabled?(:hide_vulnerability_severity_override, security_finding.project&.root_ancestor)
            raise Gitlab::Access::AccessDeniedError
          end

          result = override_severity(security_finding, severity)

          {
            uuid: result.success? ? result.payload[:security_finding][:uuid] : nil,
            security_finding: result.success? ? result.payload[:security_finding] : nil,
            errors: Array(result.message)
          }
        end

        private

        def override_severity(security_finding, severity)
          ::Security::Findings::SeverityOverrideService.new(
            user: current_user,
            security_finding: security_finding,
            severity: severity
          ).execute
        end

        def find_object(uuid:)
          ::Security::Finding.find_by_uuid(uuid)
        end
      end
    end
  end
end
