# frozen_string_literal: true

module Types
  module SecurityOrchestration # rubocop:disable Gitlab/BoundedContexts -- Existing module
    class PolicyApprovalSettingsOverrideType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorized via resolver
      graphql_name 'PolicyApprovalSettingsOverride'
      description 'Represents the approval settings of merge request overridden by a policy.'

      field :name,
        type: GraphQL::Types::String,
        null: true,
        experiment: { milestone: '17.8' },
        description: 'Policy name.'

      field :edit_path,
        type: GraphQL::Types::String,
        null: true,
        experiment: { milestone: '17.8' },
        description: 'Path to edit the policy.'

      field :settings,
        type: GraphQL::Types::JSON,
        null: false,
        description: 'Overridden project approval settings.'
    end
  end
end
