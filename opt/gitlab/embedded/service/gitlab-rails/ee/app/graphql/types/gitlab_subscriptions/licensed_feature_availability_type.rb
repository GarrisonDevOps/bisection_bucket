# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    class LicensedFeatureAvailabilityType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent is already authorized
      graphql_name 'LicensedFeatureAvailability'
      description 'Represents the availability of a licensed feature for a namespace or project.'

      def self.authorization_scopes
        super + [:ai_workflows]
      end

      field :available,
        GraphQL::Types::Boolean,
        scopes: [:api, :read_api, :ai_workflows],
        null: false,
        description: 'Whether the feature is available on the current plan.'

      field :required_plan,
        GraphQL::Types::String,
        scopes: [:api, :read_api, :ai_workflows],
        null: true,
        description: 'The minimum plan required to access this feature. ' \
          'Returns null if the required plan cannot be determined.'
    end
  end
end
