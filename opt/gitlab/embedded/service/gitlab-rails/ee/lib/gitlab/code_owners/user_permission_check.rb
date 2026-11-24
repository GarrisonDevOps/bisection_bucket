# frozen_string_literal: true

module Gitlab
  module CodeOwners
    class UserPermissionCheck
      def initialize(project, code_owners_entries, limit:)
        @project = project
        @entries = code_owners_entries
        @limit = limit
      end

      def errors
        groups = GroupsLoader.new(project, names: extracted_names).groups
        possible_usernames = extracted_names - groups.map(&:full_path)

        users = UsersLoader.new(project, names: possible_usernames).members

        # Preload for ability check
        ActiveRecord::Associations::Preloader.new(records: users, associations: :namespace_bans).call
        project.team.max_member_access_for_user_ids(users.map(&:id))

        users_with_permission = users.select do |user|
          Ability.allowed?(user, :update_merge_request, project)
        end

        error_usernames = possible_usernames - users_with_permission.map(&:username)
        entries.each_with_object([]) do |entry, errors|
          next unless Gitlab::CodeOwners::ReferenceExtractor.new(entry.owner_line).names.intersect?(error_usernames)

          errors << { error: :owner_without_permission, line_number: entry.line_number }
        end
      end

      private

      attr_reader :entries, :project, :limit

      def extracted_names
        owner_lines = entries.map(&:owner_line)
        ReferenceExtractor.new(owner_lines).names.first(limit)
      end
    end
  end
end
