# frozen_string_literal: true

module Resolvers
  module ComplianceManagement
    module MergeRequests
      class GroupComplianceViolationResolver < BaseComplianceViolationResolver
        type ::Types::ComplianceManagement::MergeRequests::ComplianceViolationType.connection_type, null: true
        description 'Compliance violations reported on a merged merge request.'

        argument :filters, Types::ComplianceManagement::MergeRequests::ComplianceViolationGroupInputType,
          required: false,
          default_value: {},
          description: 'Filters applied when retrieving compliance violations.'
      end
    end
  end
end
