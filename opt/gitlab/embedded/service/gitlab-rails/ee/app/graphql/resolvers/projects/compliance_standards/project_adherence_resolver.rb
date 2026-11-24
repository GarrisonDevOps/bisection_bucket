# frozen_string_literal: true

module Resolvers
  module Projects
    module ComplianceStandards
      class ProjectAdherenceResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        alias_method :project, :object

        type ::Types::Projects::ComplianceStandards::AdherenceType.connection_type, null: true
        description 'Compliance standards adherence for a project.'

        authorize :read_compliance_adherence_report
        authorizes_object!

        argument :filters, Types::Projects::ComplianceStandards::ProjectAdherenceInputType,
          required: false,
          default_value: {},
          description: 'Filters applied when retrieving compliance standards adherence.'

        def resolve(filters: {})
          standards_adherence_records = ::Projects::ComplianceStandards::AdherenceFinder.new(
            project.group,
            current_user,
            filters.to_h.merge({ skip_authorization: true, project_ids: [project.id] })
          ).execute

          offset_pagination(standards_adherence_records)
        end
      end
    end
  end
end
