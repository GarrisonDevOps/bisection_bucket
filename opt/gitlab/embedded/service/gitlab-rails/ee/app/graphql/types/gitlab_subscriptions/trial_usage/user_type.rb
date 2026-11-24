# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    module TrialUsage
      class UserType < BaseObject
        graphql_name 'GitlabTrialUsageUser'
        description 'Describes the user with their trial usage data'

        authorize :read_user

        field :avatar_url,
          type: GraphQL::Types::String,
          null: true,
          description: "URL of the user's avatar."
        field :id,
          type: GlobalIDType[::User],
          null: false,
          description: 'Global ID of the user.'
        field :name,
          type: GraphQL::Types::String,
          null: false,
          resolver_method: :redacted_name,
          description: 'Human-readable name of the user.'
        field :usage,
          type: Types::GitlabSubscriptions::TrialUsage::UserUsageType,
          null: true,
          description: 'Credit usage for a user during a trial.'
        field :username,
          type: GraphQL::Types::String,
          null: false,
          description: 'Username of the user. Unique within the instance of GitLab.'

        UserUsage = Struct.new(
          :total_credits,
          :credits_used,
          :declarative_policy_subject
        )

        def usage
          BatchLoader::GraphQL.for(object.id).batch do |user_ids, loader|
            load_users_usage(user_ids, loader)
          end
        end

        def redacted_name
          object.redacted_name(context[:current_user])
        end

        private

        def load_users_usage(user_ids, loader)
          result = context[:subscription_usage_client].get_trial_usage_for_user_ids(user_ids)

          return unless result[:usersUsage]

          result[:usersUsage].each do |usage|
            loader.call(
              usage[:userId],
              UserUsage.new(
                total_credits: usage[:totalCredits],
                credits_used: usage[:creditsUsed],
                declarative_policy_subject: object
              )
            )
          end
        end
      end
    end
  end
end
