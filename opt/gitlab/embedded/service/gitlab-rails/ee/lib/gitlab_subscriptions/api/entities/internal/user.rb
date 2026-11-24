# frozen_string_literal: true

module GitlabSubscriptions
  module API
    module Entities
      module Internal
        class User < ::API::Entities::UserSafe
          expose :web_url, documentation: { type: 'String', example: 'https://gitlab.example.com/root' } do |user, _opt|
            Gitlab::Routing.url_helpers.user_url(user)
          end
        end
      end
    end
  end
end
