# frozen_string_literal: true

module Types
  module Ai
    module DapFactory
      # rubocop:disable Graphql/AuthorizeTypes -- authorized by the resolver that returns it
      class AutoReviewType < BaseObject
        graphql_name 'DapFactoryAutoReview'
        authorize_granular_token parent_authorizes: :update_ai_flow_trigger
        description 'Duo Code Review settings that the Review stage of a DAP Software Factory depends on.'

        field :available, GraphQL::Types::Boolean,
          null: false,
          method: :available?,
          description: 'Whether Duo Code Review can run automatically in the project.'

        field :enabled, GraphQL::Types::Boolean,
          null: false,
          method: :enabled?,
          description: 'Whether GitLab Duo reviews new merge requests automatically.'

        field :decisions_enabled, GraphQL::Types::Boolean,
          null: false,
          method: :decisions_enabled?,
          description: 'Whether GitLab Duo can approve and request changes.'

        field :locked, GraphQL::Types::Boolean,
          null: false,
          method: :locked?,
          description: 'Whether a group or the instance has locked the setting.'
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
