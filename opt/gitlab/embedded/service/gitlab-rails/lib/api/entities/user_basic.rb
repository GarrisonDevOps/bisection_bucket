# frozen_string_literal: true

module API
  module Entities
    class UserBasic < UserSafe
      expose :state,
        documentation: { type: 'String', example: 'active',
                         desc: 'State of the user account. Possible values: `active`, `blocked`, `ldap_blocked`, ' \
                           '`blocked_pending_approval`, `banned`, or `deactivated`.' }
      expose :access_locked?, as: :locked,
        documentation: { type: 'Boolean',
                         desc: 'If `true`, the user account is locked, and the user cannot sign in until the lock ' \
                           'expires or an administrator unlocks the account.' }

      expose :avatar_url,
        documentation: { type: 'String', example: 'https://gravatar.com/avatar/1',
                         desc: "URL of the user's avatar." } do |user, options|
        user.avatar_url(only_path: false)
      end

      expose(
        :avatar_path,
        documentation: {
          type: 'String',
          example: '/user/avatar/28/The-Big-Lebowski-400-400.png'
        },
        if: ->(user, options) { options.fetch(:only_path, false) && user.avatar_path }
      )

      expose :custom_attributes, using: ::API::Entities::CustomAttribute, if: :with_custom_attributes,
        documentation: { is_array: true }

      expose :web_url,
        documentation: { type: 'String', example: 'https://gitlab.example.com/root',
                         desc: "URL of the user's profile." } do |user, options|
        Gitlab::Routing.url_helpers.user_url(user)
      end
    end
  end
end

API::Entities::UserBasic.prepend_mod_with('API::Entities::UserBasic')
