# frozen_string_literal: true

module Types
  module Projects
    # rubocop: disable Graphql/AuthorizeTypes -- parent handles auth
    class DuoContextExclusionSettingsType < BaseObject
      graphql_name 'DuoContextExclusionSettings'
      description 'Settings for Duo context exclusion rules'

      authorize_granular_token parent_authorizes: :read_project

      def self.authorization_scopes
        super + [:ai_workflows]
      end

      field :exclusion_rules,
        [String],
        null: true,
        description: 'List of rules for excluding files from Duo context.',
        scopes: [:api, :read_api, :ai_workflows]
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
