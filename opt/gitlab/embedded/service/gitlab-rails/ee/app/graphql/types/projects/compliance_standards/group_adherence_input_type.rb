# frozen_string_literal: true

module Types
  module Projects
    module ComplianceStandards
      class GroupAdherenceInputType < ProjectAdherenceInputType
        graphql_name 'ComplianceStandardsAdherenceInput'

        argument :project_ids, [::Types::GlobalIDType[::Project]],
          required: false,
          description: 'Filter compliance standards adherence by project.',
          prepare: ->(ids, _ctx) { ids.map(&:model_id) }
      end
    end
  end
end
