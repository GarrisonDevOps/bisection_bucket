# frozen_string_literal: true

module Types
  module Admin
    module CloudLicenses
      # rubocop: disable Graphql/AuthorizeTypes
      class CurrentLicenseType < BaseObject
        graphql_name 'CurrentLicense'
        description 'Represents the current license'

        include ::Types::Admin::CloudLicenses::LicenseType

        field :last_sync, ::Types::TimeType,
          null: true,
          description: 'Date when the license was last synced.',
          method: :last_synced_at

        field :billable_users_count, GraphQL::Types::Int,
          null: true,
          description: 'Number of billable users on the system.',
          method: :daily_billable_users_count

        field :maximum_user_count, GraphQL::Types::Int,
          null: true,
          description: 'Highest number of billable users on the system during the term of the current license.'

        field :users_over_license_count, GraphQL::Types::Int,
          null: true,
          description: 'Number of users over the paid users in the license.',
          method: :overage_with_historical_max

        field :trial, GraphQL::Types::Boolean,
          null: true,
          description: 'Indicates if the license is a trial.',
          method: :trial?

        field :subscription_name, GraphQL::Types::String,
          null: true,
          description: 'Name of the subscription in the Customers Portal.'

        field :has_gitlab_credits_add_on, GraphQL::Types::Boolean,
          null: false,
          description: 'Whether the license has an active GitLab Credits add-on.'

        def has_gitlab_credits_add_on # rubocop:disable Naming/PredicatePrefix -- GraphQL field resolver, not a Ruby predicate
          ::License.has_active_gitlab_credits_add_on?
        end
      end
    end
  end
end
