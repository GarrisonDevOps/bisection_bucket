# frozen_string_literal: true

module Gitlab
  module CodeOwners
    class UsersLoader
      include Gitlab::Utils::StrongMemoize

      def initialize(project, emails: nil, names: nil)
        @project = project
        @emails = emails
        @names = names
      end

      # Generate a list of all project members who are mentioned in the
      #   CODEOWNERS file, and load them to the matching entry.
      #
      def load_to(entries)
        entries.each do |entry|
          entry.add_matching_users_from(members)
        end
      end

      def members
        project.members_among(users)
      end
      strong_memoize_attr :members

      private

      attr_reader :project, :names, :emails

      def users
        return User.none if names.blank? && emails.blank?

        relations = []
        relations << User.by_any_email(emails) if emails.present?
        relations << User.by_username(names) if names.present?

        User.from_union(relations).with_emails.active
      end
    end
  end
end
