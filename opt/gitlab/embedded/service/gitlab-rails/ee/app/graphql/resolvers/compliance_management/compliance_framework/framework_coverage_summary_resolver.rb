# frozen_string_literal: true

module Resolvers
  module ComplianceManagement
    module ComplianceFramework
      class FrameworkCoverageSummaryResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        alias_method :group, :object

        type ::Types::ComplianceManagement::ComplianceFramework::FrameworkCoverageSummaryType,
          null: true
        description 'Overall summary of compliance framework coverage.'

        authorize :read_compliance_dashboard
        authorizes_object!

        def resolve(**_args)
          project_ids = group.all_active_project_ids

          return { total_projects: 0, covered_count: 0 } unless project_ids.any?

          total_projects_count = project_ids.length
          covered_count = ::ComplianceManagement::ComplianceFramework::ProjectSettings
                            .covered_projects_count(project_ids)

          {
            total_projects: total_projects_count,
            covered_count: covered_count
          }
        end
      end
    end
  end
end
