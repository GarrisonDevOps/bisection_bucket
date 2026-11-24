# frozen_string_literal: true

module Gitlab
  module CodeOwners
    module OwnerValidation
      class EligibleApproversFilter
        include ::Gitlab::Utils::StrongMemoize

        def initialize(project, users:, usernames:, emails:)
          @project = project
          @input_users = users
          @input_usernames = usernames
          @input_emails = emails
        end

        def error_message
          :owner_without_permission
        end

        def output_users
          ActiveRecord::Associations::Preloader.new(
            records: input_users, associations: %i[namespace_bans emails]
          ).call
          project.team.max_member_access_for_user_ids(input_users.map(&:id))

          input_users.select { |user| Ability.allowed?(user, :update_merge_request, project) }
        end
        strong_memoize_attr :output_users

        def invalid_usernames
          input_usernames.reject do |input_username|
            output_users_username_set.include?(input_username.downcase)
          end
        end
        strong_memoize_attr :invalid_usernames

        def valid_usernames
          input_usernames - invalid_usernames
        end
        strong_memoize_attr :valid_usernames

        def invalid_emails
          input_emails - output_users.flat_map(&:verified_emails)
        end
        strong_memoize_attr :invalid_emails

        def valid_emails
          input_emails - invalid_emails
        end
        strong_memoize_attr :valid_emails

        def valid_entry?(references)
          valid_references?(references.names, invalid_usernames) &&
            valid_references?(references.emails, invalid_emails)
        end

        private

        attr_reader :project, :input_users, :input_usernames, :input_emails

        def valid_references?(references, invalid_references)
          !references.intersect?(invalid_references)
        end

        def output_users_username_set
          output_users.map { |user| user.username.downcase }.to_set
        end
        strong_memoize_attr :output_users_username_set
      end
    end
  end
end
