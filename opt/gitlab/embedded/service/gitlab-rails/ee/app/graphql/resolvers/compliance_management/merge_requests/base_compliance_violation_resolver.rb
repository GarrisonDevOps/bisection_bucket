# frozen_string_literal: true

module Resolvers
  module ComplianceManagement
    module MergeRequests
      class BaseComplianceViolationResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        type ::Types::ComplianceManagement::MergeRequests::ComplianceViolationType.connection_type, null: true
        description 'Compliance violations reported on a merged merge request.'

        alias_method :project_or_group, :object

        authorize :read_compliance_violations_report
        authorizes_object!

        argument :sort, ::Types::ComplianceManagement::MergeRequests::ComplianceViolationSortEnum,
          required: false,
          default_value: 'SEVERITY_LEVEL_DESC',
          description: 'List compliance violations by sort order.'

        def resolve(filters: {}, sort: 'SEVERITY_LEVEL_DESC')
          violations = ::ComplianceManagement::MergeRequests::ComplianceViolationsFinder.new(
            current_user: current_user,
            project_or_group: project_or_group,
            params: filters.to_h.merge(sort: sort)).execute

          offset_pagination(violations)
        end
      end
    end
  end
end
