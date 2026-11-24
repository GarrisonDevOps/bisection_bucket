# frozen_string_literal: true

module Types
  module Issuables
    class CustomFieldSelectOptionType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- already authroized in parent entity
      graphql_name 'CustomFieldSelectOption'
      description 'Represents a custom field select option'

      authorize_granular_token skip_reason: :parent_authorizes

      def self.authorization_scopes
        super + [:ai_workflows]
      end

      field :id, ::Types::GlobalIDType[::Issuables::CustomFieldSelectOption],
        null: false, description: 'Global ID of the custom field select option.',
        scopes: [:api, :read_api, :ai_workflows]

      field :value, GraphQL::Types::String,
        null: false, description: 'Value of the custom field select option.',
        scopes: [:api, :read_api, :ai_workflows]
    end
  end
end
