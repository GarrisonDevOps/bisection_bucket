# frozen_string_literal: true

module API
  class UserCounts < ::API::Base
    feature_category :navigation
    urgency :low

    resource :user_counts do
      desc 'Return the user specific counts' do
        detail 'Returns counts for the current user: open issues and active merge requests assigned to the user, ' \
          'merge requests the user is requested to review, and pending to-do items.'
        success Entities::UserCounts
        failure [
          { code: 401, message: 'Unauthorized' }
        ]
        tags ['users']
      end
      route_setting :authorization, permissions: :read_user_counts, boundary_type: :user
      get do
        unauthorized! unless current_user

        present current_user, with: Entities::UserCounts
      end
    end
  end
end
