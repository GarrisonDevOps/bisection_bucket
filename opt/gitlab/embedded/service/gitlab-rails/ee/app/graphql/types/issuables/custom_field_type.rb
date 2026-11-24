# frozen_string_literal: true

module Types
  module Issuables
    class CustomFieldType < BaseObject
      graphql_name 'CustomField'
      description 'Represents a custom field'

      connection_type_class Types::CountableConnectionType

      authorize :read_custom_field
      authorize_granular_token skip_reason: :parent_authorizes

      def self.authorization_scopes
        super + [:ai_workflows]
      end

      field :id, ::Types::GlobalIDType[::Issuables::CustomField],
        null: false, description: 'Global ID of the custom field.',
        scopes: [:api, :read_api, :ai_workflows]

      field :name, GraphQL::Types::String,
        null: false, description: 'Name of the custom field.',
        scopes: [:api, :read_api, :ai_workflows]

      field :field_type, ::Types::Issuables::CustomFieldTypeEnum,
        null: false, description: 'Type of custom field.',
        scopes: [:api, :read_api, :ai_workflows]

      field :active, GraphQL::Types::Boolean,
        null: false, description: 'Whether the custom field is active.',
        method: :active?,
        scopes: [:api, :read_api, :ai_workflows]

      field :created_at, Types::TimeType,
        null: false, description: 'Timestamp when the custom field was created.'

      field :created_by, Types::UserType, null: true, # rubocop:disable GraphQL/ExtractType -- no need to extract to created
        description: 'User that created the custom field.'

      field :updated_at, Types::TimeType,
        null: false, description: 'Timestamp when the custom field was last updated.'

      field :updated_by, Types::UserType, null: true, # rubocop:disable GraphQL/ExtractType -- no need to extract to updated
        description: 'User that last updated the custom field.'

      field :select_options, [Types::Issuables::CustomFieldSelectOptionType],
        null: true, description: 'Available options for a select field.'

      field :work_item_types, [Types::WorkItems::TypeType],
        null: true, description: 'Work item types that the custom field is available on.'
    end
  end
end
