# frozen_string_literal: true

module Resolvers
  module ComplianceManagement
    module ComplianceFramework
      class FrameworkCoverageDetailsResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        alias_method :group, :object

        type ::Types::ComplianceManagement::ComplianceFramework::FrameworkCoverageDetailType.connection_type,
          null: true
        description 'Compliance frameworks with their project coverage counts.'

        authorize :read_compliance_dashboard
        authorizes_object!

        def resolve(**_args)
          return unless group

          project_ids = group.all_active_project_ids
          return [] unless project_ids.any?

          root_group = group.root_ancestor
          framework_ids = root_group.compliance_framework_ids_with_csp

          frameworks = ::ComplianceManagement::FrameworkCoverageDetailsFinder.new(
            framework_ids: framework_ids,
            project_ids: project_ids
          ).execute

          paginated_data = offset_pagination(frameworks)

          paginated_data.map do |framework|
            ::ComplianceManagement::FrameworkCoverageDetails.new(
              framework
            )
          end
        end
      end
    end
  end
end
