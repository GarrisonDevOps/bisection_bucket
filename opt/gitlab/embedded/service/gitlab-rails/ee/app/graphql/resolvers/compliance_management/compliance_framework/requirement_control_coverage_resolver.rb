# frozen_string_literal: true

module Resolvers
  module ComplianceManagement
    module ComplianceFramework
      class RequirementControlCoverageResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        alias_method :group, :object

        type ::Types::ComplianceManagement::ComplianceFramework::RequirementControlCoverageType,
          null: true
        description 'Compliance control coverage statistics across all requirements.'

        authorize :read_compliance_dashboard
        authorizes_object!

        def resolve(**_args)
          project_ids = group.all_project_ids
          return { passed: 0, failed: 0, pending: 0, not_applicable: 0 } unless project_ids.any?

          stats = ::ComplianceManagement::ComplianceFramework::ProjectControlComplianceStatus
                    .control_coverage_statistics(project_ids)

          {
            passed: stats.fetch('pass', 0),
            failed: stats.fetch('fail', 0),
            pending: stats.fetch('pending', 0),
            not_applicable: stats.fetch('not_applicable', 0)
          }
        end
      end
    end
  end
end
