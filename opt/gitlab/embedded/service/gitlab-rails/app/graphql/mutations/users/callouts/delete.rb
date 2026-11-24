# frozen_string_literal: true

module Mutations
  module Users
    module Callouts
      class Delete < ::Mutations::BaseMutation
        graphql_name 'UserCalloutDelete'

        authorize_granular_token permissions: :dismiss_ui_notification,
          boundary: :user,
          boundary_type: :user

        argument :feature_name,
          GraphQL::Types::String,
          required: true,
          description: "Feature name of the callout dismissal to delete."

        field :user_callout, Types::UserCalloutType,
          null: true,
          description: 'User callout deleted. Null if the callout was not dismissed.'

        def resolve(feature_name:)
          callout = find_callout(feature_name)
          return { user_callout: nil, errors: [] } unless callout

          callout.destroy

          {
            user_callout: callout,
            errors: errors_on_object(callout)
          }
        end

        private

        def find_callout(feature_name)
          return unless ::Users::Callout.feature_names.key?(feature_name)

          current_user.callouts.with_feature_name(feature_name).first
        end
      end
    end
  end
end
