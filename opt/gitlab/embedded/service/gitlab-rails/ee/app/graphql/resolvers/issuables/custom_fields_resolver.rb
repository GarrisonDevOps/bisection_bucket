# frozen_string_literal: true

module Resolvers
  module Issuables
    class CustomFieldsResolver < BaseResolver
      include LooksAhead
      include ::Issuables::CustomFields::LookAheadPreloads

      type Types::Issuables::CustomFieldType.connection_type, null: true

      argument :active, GraphQL::Types::Boolean,
        required: false,
        description: 'Filter for active fields. If `false`, excludes active fields. ' \
          'If `true`, returns only active fields.'

      argument :field_type, ::Types::Issuables::CustomFieldTypeEnum,
        required: false,
        description: 'Filter for selected field type.'

      argument :search, GraphQL::Types::String,
        required: false,
        description: 'Search query for custom field name.'

      argument :work_item_type_id, Types::GlobalIDType[::WorkItems::Type],
        required: false,
        description: 'Filter custom fields associated to the given work item type.',
        prepare: ->(work_item_typ_id, _ctx) { work_item_typ_id&.model_id }

      def resolve_with_lookahead(active: nil, field_type: nil, search: nil, work_item_type_id: nil)
        work_item_type_ids = [work_item_type_id] unless work_item_type_id.nil?

        custom_fields = ::Issuables::CustomFieldsFinder.new(
          current_user,
          group: object.root_ancestor,
          active: active,
          field_type: field_type,
          search: search,
          work_item_type_ids: work_item_type_ids
        ).execute

        offset_pagination(
          apply_lookahead(custom_fields)
        )
      end

      alias_method :preloads, :custom_field_preloads
    end
  end
end
