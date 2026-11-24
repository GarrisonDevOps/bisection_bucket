# frozen_string_literal: true

module Resolvers
  module ComplianceManagement
    module ComplianceFramework
      class RequirementCoverageResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        alias_method :group, :object

        type ::Types::ComplianceManagement::ComplianceFramework::RequirementCoverageType,
          null: true
        description 'Compliance requirement coverage statistics for the group.'

        authorize :read_compliance_dashboard
        authorizes_object!

        def resolve(**_args)
          return unless group.present?

          project_ids = group.all_project_ids

          return { passed: 0, failed: 0, pending: 0, not_applicable: 0 } unless project_ids.any?

          stats = ::ComplianceManagement::ComplianceFramework::ProjectRequirementComplianceStatus
                    .coverage_statistics(project_ids)

          {
            passed: stats[:passed],
            failed: stats[:failed],
            pending: stats[:pending],
            not_applicable: stats[:not_applicable]
          }
        end
      end
    end
  end
end
