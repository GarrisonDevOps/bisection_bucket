# frozen_string_literal: true

module Types
  module GitlabSubscriptions
    class AddOnUserType < UserType
      graphql_name 'AddOnUser'
      description 'A user with add-on data'

      authorize :read_user

      field :add_on_assignments,
        type: ::Types::GitlabSubscriptions::UserAddOnAssignmentType.connection_type,
        resolver: ::Resolvers::GitlabSubscriptions::UserAddOnAssignmentsResolver,
        description: 'Add-on purchase assignments for the user.',
        experiment: { milestone: '16.4' }

      field :last_login_at,
        type: Types::TimeType,
        null: true,
        method: :current_sign_in_at,
        description: 'Timestamp of the last sign in.'

      field :last_duo_activity_on, # rubocop:disable GraphQL/ExtractType -- suggestion doesn't make any sense
        type: Types::DateType,
        description: 'Date of the last Duo activity of the user. Refreshed on any GitLab Duo activity.'

      def last_duo_activity_on
        lazy_ai_user_metrics = BatchLoader::GraphQL.for(object.id).batch do |user_ids, loader|
          ::Ai::UserMetrics.for_users(user_ids).each do |metric|
            loader.call(metric.user_id, metric)
          end
        end

        Gitlab::Graphql::Lazy.with_value(lazy_ai_user_metrics) do |metrics|
          metrics&.last_duo_activity_on
        end
      end
    end
  end
end
