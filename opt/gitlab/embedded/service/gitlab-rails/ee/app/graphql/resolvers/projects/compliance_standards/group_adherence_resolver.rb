# frozen_string_literal: true

module Resolvers
  module Projects
    module ComplianceStandards
      class GroupAdherenceResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        alias_method :group, :object

        type ::Types::Projects::ComplianceStandards::AdherenceType.connection_type, null: true
        description 'Compliance standards adherence for a project.'

        authorize :read_compliance_adherence_report
        authorizes_object!

        argument :filters, Types::Projects::ComplianceStandards::GroupAdherenceInputType,
          required: false,
          default_value: {},
          description: 'Filters applied when retrieving compliance standards adherence.'

        def resolve(filters: {})
          standards_adherence_records = ::Projects::ComplianceStandards::AdherenceFinder.new(
            group,
            current_user,
            filters.to_h.merge({ include_subgroups: true })
          ).execute

          offset_pagination(standards_adherence_records)
        end
      end
    end
  end
end
