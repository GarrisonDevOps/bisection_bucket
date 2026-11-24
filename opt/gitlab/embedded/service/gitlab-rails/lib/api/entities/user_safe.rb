# frozen_string_literal: true

module API
  module Entities
    class UserSafe < Grape::Entity
      include RequestAwareEntity

      expose :id, documentation: { type: 'Integer', format: 'int64', example: 1, desc: 'ID of the user.' }
      expose :username, documentation: { type: 'String', example: 'admin', desc: 'Username of the user.' }
      expose :public_email,
        documentation: { type: 'String', example: 'john@example.com', desc: 'Public email address of the user.' }
      expose :name,
        documentation: { type: 'String', example: 'Administrator',
                         desc: 'Name of the user. For a bot user, `****` if the current user cannot read ' \
                           "the bot's project or group." } do |user|
        current_user = request.respond_to?(:current_user) ? request.current_user : options.fetch(:current_user, nil)

        user.redacted_name(current_user)
      end
    end
  end
end
