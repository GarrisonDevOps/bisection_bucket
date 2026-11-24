# frozen_string_literal: true

module Resolvers
  module ComplianceManagement
    module Projects
      class GroupViolationsResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        alias_method :group, :object

        type ::Types::ComplianceManagement::Projects::ComplianceViolationType.connection_type,
          null: true
        description 'Compliance violations for projects under the group and its subgroups.'

        authorize :read_compliance_violations_report
        authorizes_object!

        argument :filters, ::Types::ComplianceManagement::Projects::ComplianceViolationFilterInputType,
          required: false,
          default_value: {},
          description: 'Filters applied when retrieving compliance violations.'

        def resolve(**args)
          violation_records = ::ComplianceManagement::Projects::ComplianceViolationFinder.new(
            group,
            current_user,
            args[:filters].to_h
          ).execute

          offset_pagination(violation_records)
        end
      end
    end
  end
end
