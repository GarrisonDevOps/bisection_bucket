# frozen_string_literal: true

module Resolvers
  module ComplianceManagement
    module ComplianceFramework
      class ProjectControlStatusResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        alias_method :project, :object

        type ::Types::ComplianceManagement::ComplianceFramework::ProjectControlStatusType.connection_type,
          null: true
        description 'Compliance control statuses for a project.'

        authorize :read_compliance_adherence_report
        authorizes_object!

        argument :filters, Types::ComplianceManagement::ComplianceFramework::ProjectControlStatusInputType,
          required: false,
          default_value: {},
          description: 'Filters applied when retrieving compliance control statuses for the project.'

        def resolve(filters: {})
          control_status_records = ::ComplianceManagement::ComplianceFramework::ProjectControlStatusFinder.new(
            project,
            current_user,
            filters.to_h
          ).execute

          offset_pagination(control_status_records)
        end
      end
    end
  end
end
