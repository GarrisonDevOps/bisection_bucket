# frozen_string_literal: true

module Projects
  module Members
    class EffectiveAccessLevelPerUserFinder < EffectiveAccessLevelFinder
      # @param user [User, Integer, Array<User, Integer>] one or more users, or their IDs
      def initialize(project, user)
        @project = project
        @user_ids = Array(user).map { |u| u.is_a?(::User) ? u.id : u }
      end

      def execute
        return [] if user_ids.empty?

        super
      end

      private

      attr_reader :user_ids

      def apply_scopes(members)
        super.where(user_id: user_ids) # rubocop: disable CodeReuse/ActiveRecord -- the finder narrows the inherited members query to these users
      end
    end
  end
end
