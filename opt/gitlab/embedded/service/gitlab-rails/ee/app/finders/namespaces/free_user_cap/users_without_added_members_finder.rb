# frozen_string_literal: true

module Namespaces
  module FreeUserCap
    class UsersWithoutAddedMembersFinder
      def self.count(group, ignored_member_ids, limit)
        instance = new(group, ignored_member_ids, limit)
        instance.count
      end

      def initialize(group, ignored_member_ids, limit)
        @group = group
        @ids = []
        @ignored_member_ids = ignored_member_ids
        @limit = limit
      end

      def count
        build_ids

        members = Member.id_in(member_ids_without_ignored_ids)

        # The merge_condition to handle the billed_project_members where it is passed in the billed_project_users.
        # The other cases have that condition in the member methods and AR will de-duplicate the add for them here.
        group
          .billed_users_from_members(members, merge_condition: ::User.with_state(:active))
          .allow_cross_joins_across_databases(
            url: 'https://gitlab.com/gitlab-org/gitlab/-/issues/417464'
          )
          .limit(limit)
          .count
      end

      private

      attr_reader :group, :ids, :ignored_member_ids, :limit

      METHOD_MAP = [
        :billed_group_members,
        :billed_project_members,
        :billed_shared_group_members,
        :billed_invited_group_to_project_members
      ].freeze

      def build_ids
        METHOD_MAP.each { |method_name| append_to_member_ids(execute_query_method(method_name)) }
      end

      def execute_query_method(method_name)
        group.public_send(method_name) # rubocop:disable GitlabSecurity/PublicSend -- Rules do not fit in this case as we aren't being driven off params
             .allow_cross_joins_across_databases(url: 'https://gitlab.com/gitlab-org/gitlab/-/issues/417464')
             .pluck(:id) # rubocop:disable CodeReuse/ActiveRecord -- Rules do not fit in this case
      end

      def append_to_member_ids(member_ids)
        @ids += member_ids
      end

      def member_ids_without_ignored_ids
        ids - ignored_member_ids
      end
    end
  end
end
