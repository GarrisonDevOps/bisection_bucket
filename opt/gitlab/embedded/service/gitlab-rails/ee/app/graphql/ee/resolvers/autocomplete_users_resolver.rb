# frozen_string_literal: true

module EE
  module Resolvers
    module AutocompleteUsersResolver # rubocop:disable Gitlab/BoundedContexts -- EE extension of CE AutocompleteUsersResolver
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      override :resolve
      def resolve(**args)
        users = super

        if args[:lookahead].selection(:merge_request_interaction)&.selects?(:can_merge)
          project.team.max_member_access_for_user_ids(users.map(&:id))
          ActiveRecord::Associations::Preloader.new(records: users, associations: :namespace_bans).call
        end

        users
      end
    end
  end
end
