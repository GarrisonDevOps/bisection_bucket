# frozen_string_literal: true

module API
  module Entities
    class User < UserBasic
      include ::UsersHelper
      include TimeZoneHelper
      include Gitlab::Utils::StrongMemoize

      expose :created_at,
        documentation: { type: 'DateTime', desc: 'Creation date and time of the user account in ISO 8601 format.' },
        if: ->(user, opts) { Ability.allowed?(opts[:current_user], :read_user_profile, user) }
      expose :bio, documentation: { type: 'String', desc: 'Biography of the user.' }
      expose :location, documentation: { type: 'String', desc: 'Location of the user.' }
      expose :linkedin, documentation: { type: 'String', desc: 'LinkedIn username of the user.' }
      expose :twitter, documentation: { type: 'String', desc: 'Twitter username of the user.' }
      expose :discord, documentation: { type: 'String', desc: 'Discord user ID of the user.' }
      expose :website_url, documentation: { type: 'String', desc: 'Website of the user.' }
      expose :github, documentation: { type: 'String', desc: 'GitHub username of the user.' }
      expose :job_title, documentation: { type: 'String', desc: 'Job title of the user.' }
      expose :pronouns, documentation: { type: 'String', desc: 'Pronouns of the user.' }
      # rubocop:disable Style/SymbolProc -- we're not able to pass &:company as this tries to pass Grape::Entity::Options to said method
      expose :organization, documentation: { type: 'String', desc: 'Organization of the user.' } do |user|
        user.company
      end
      # rubocop:enable Style/SymbolProc
      expose :bot?, as: :bot, documentation: { type: 'Boolean' }
      expose :work_information do |user|
        work_information(user)
      end
      expose :followers, if: ->(user, opts) { Ability.allowed?(opts[:current_user], :read_user_profile, user) && following_users_allowed(opts[:current_user], user) } do |user|
        user.followers.size
      end
      expose :following, if: ->(user, opts) { Ability.allowed?(opts[:current_user], :read_user_profile, user) && following_users_allowed(opts[:current_user], user) } do |user|
        user.followees.size
      end
      expose :is_followed, if: ->(user, opts) { Ability.allowed?(opts[:current_user], :read_user_profile, user) && opts[:current_user] && following_users_allowed(opts[:current_user], user) } do |user, opts|
        user.followed_by?(opts[:current_user])
      end
      expose :local_time do |user|
        local_time(user.timezone)
      end

      def following_users_allowed(current_user, user)
        strong_memoize(:following_users_allowed) do
          if current_user
            current_user.following_users_allowed?(user)
          else
            true
          end
        end
      end
    end
  end
end
