# frozen_string_literal: true

module API
  module Entities
    class UserActivity < Grape::Entity
      expose :username, documentation: { type: 'String', example: 'johndoe' }
      expose :last_activity_on, documentation: {
        type: 'Date', example: '2015-12-24',
        desc: 'Date of the last activity of the user. Updated by Git HTTP or SSH activity such as clone and ' \
          'push, signing in, visiting dashboard, project, issue, and merge request pages, and using the REST or ' \
          'GraphQL API.'
      }
      # Back-compat
      expose :last_activity_on, as: :last_activity_at,
        documentation: { type: 'Date', example: '2015-12-24', desc: 'Deprecated. Use `last_activity_on` instead.' }
    end
  end
end
