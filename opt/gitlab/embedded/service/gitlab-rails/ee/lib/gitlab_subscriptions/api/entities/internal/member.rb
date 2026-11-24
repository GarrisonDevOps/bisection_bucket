# frozen_string_literal: true

module GitlabSubscriptions
  module API
    module Entities
      module Internal
        class Member < Grape::Entity
          expose :user, using: ::API::Entities::UserSafe

          # rubocop:disable API/AccessLevelStringType -- Introduced before the cop
          expose :access_level, documentation: { type: 'Integer', example: 50 }
          # rubocop:enable API/AccessLevelStringType

          expose :notification_email, documentation: { type: 'String', example: 'email@example.com' } do |member, opts|
            member.user.notification_email_for(opts[:namespace])
          end
        end
      end
    end
  end
end
