# frozen_string_literal: true

module Resolvers
  module ComplianceManagement
    module ComplianceFramework
      class GroupProjectRequirementStatusResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        alias_method :group, :object

        type ::Types::ComplianceManagement::ComplianceFramework::ProjectRequirementStatusType.connection_type,
          null: true
        description 'Compliance requirement statuses for a project.'

        authorize :read_compliance_adherence_report
        authorizes_object!

        argument :filters, Types::ComplianceManagement::ComplianceFramework::GroupProjectRequirementStatusInputType,
          required: false,
          default_value: {},
          description: 'Filters applied when retrieving compliance requirement statuses.'

        argument :order_by, Types::ComplianceManagement::ComplianceFramework::ProjectRequirementStatusOrderByEnum,
          required: false,
          description: 'Field used to sort compliance requirement statuses.'

        def resolve(**args)
          requirement_status_records = ::ComplianceManagement::ComplianceFramework::ProjectRequirementStatusFinder.new(
            group,
            current_user,
            args[:filters].to_h.merge(order_by: args[:order_by])
          ).execute

          offset_pagination(requirement_status_records)
        end
      end
    end
  end
end
