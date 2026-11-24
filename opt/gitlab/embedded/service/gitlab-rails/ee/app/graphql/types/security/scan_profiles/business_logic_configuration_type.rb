# frozen_string_literal: true

module Types
  module Security
    module ScanProfiles
      # rubocop:disable Graphql/AuthorizeTypes -- Authorization occurs at parent level (ScanProfileType)
      class BusinessLogicConfigurationType < BaseObject
        graphql_name 'BusinessLogicConfiguration'
        description 'Configuration for a business logic scan profile.'

        authorize_granular_token skip_reason: :parent_authorizes

        field :post_review_threads, GraphQL::Types::Boolean,
          null: true,
          experiment: { milestone: '19.7' },
          description: 'Indicates whether findings are posted as review threads on merge requests.'
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
