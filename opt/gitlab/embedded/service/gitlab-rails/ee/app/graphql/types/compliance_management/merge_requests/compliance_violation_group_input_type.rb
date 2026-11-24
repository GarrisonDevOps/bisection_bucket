# frozen_string_literal: true

module Types
  module ComplianceManagement
    module MergeRequests
      class ComplianceViolationGroupInputType < ComplianceViolationProjectInputType
        graphql_name 'ComplianceViolationInput'

        argument :project_ids, [::Types::GlobalIDType[::Project]],
          required: false,
          description: 'Filter compliance violations by project.',
          prepare: ->(ids, _ctx) { ids.map(&:model_id) }
      end
    end
  end
end
