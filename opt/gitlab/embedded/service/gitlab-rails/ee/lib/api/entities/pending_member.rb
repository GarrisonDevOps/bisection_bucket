# frozen_string_literal: true

module API
  module Entities
    class PendingMember < Grape::Entity
      expose :id, documentation: { type: 'Integer' }
      expose :user_name, as: :name, documentation: { type: 'String' }, if: ->(_) { user.present? }
      expose :user_username, as: :username, documentation: { type: 'String' }, if: ->(_) { user.present? }
      expose :email, documentation: { type: 'String' }
      expose :web_url, documentation: { type: 'String' }, if: ->(_) { user.present? }
      expose :invite?, as: :invited, documentation: { type: 'Boolean' }

      expose :avatar_url, documentation: { type: 'String' } do |_|
        user&.avatar_url || GravatarService.new.execute(email)
      end

      expose :active?, as: :approved, documentation: { type: 'Boolean' }

      def email
        object.invite_email || object.user.public_email
      end

      def web_url
        Gitlab::Routing.url_helpers.user_url(user)
      end

      def user
        object.user
      end
    end
  end
end
