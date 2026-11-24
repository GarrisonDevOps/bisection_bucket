# frozen_string_literal: true

module Types
  module Security
    class AttributeFilterInputType < Types::BaseInputObject
      graphql_name 'AttributeFilterInput'
      description 'Input type for filtering projects by security attributes'

      MAX_ATTRIBUTES = 20

      argument :operator, Types::Security::AttributeFilterOperatorEnum,
        required: true,
        description: 'Operator to apply for the attribute filter.'

      argument :attributes, [Types::GlobalIDType[::Security::Attribute]],
        required: true,
        description: "Global IDs of the security attributes to filter by. Up to #{MAX_ATTRIBUTES} values.",
        validates: { length: { maximum: MAX_ATTRIBUTES } },
        prepare: ->(global_ids, _ctx) {
          global_ids.filter_map do |global_id|
            GitlabSchema.parse_gid(global_id)&.model_id&.to_i
          end
        }
    end
  end
end
