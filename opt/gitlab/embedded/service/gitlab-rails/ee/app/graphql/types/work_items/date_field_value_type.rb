# frozen_string_literal: true

module Types
  module WorkItems
    class DateFieldValueType < Types::BaseObject # rubocop:disable Graphql/AuthorizeTypes -- already authorized in parent entity
      graphql_name 'WorkItemDateFieldValue'

      authorize_granular_token skip_reason: :parent_authorizes

      implements Types::WorkItems::CustomFieldValueInterface

      def self.authorization_scopes
        super + [:ai_workflows]
      end

      field :value, ::Types::DateType, null: true, description: 'Date value of the custom field.',
        scopes: [:api, :read_api, :ai_workflows]
    end
  end
end
