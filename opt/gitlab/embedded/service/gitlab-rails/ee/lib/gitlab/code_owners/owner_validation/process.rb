# frozen_string_literal: true

module Gitlab
  module CodeOwners
    module OwnerValidation
      class Process
        include ::Gitlab::Utils::StrongMemoize

        # Maxmimum number of references to validate
        # This maximum is currently not based on any benchmark
        MAX_REFERENCES = 200

        def initialize(project, file, max_references_limit: MAX_REFERENCES)
          @project = project
          @file = file
          @max_references_limit = max_references_limit
          @entries = file.parsed_data.values.flat_map(&:values)
        end

        def execute
          # Avoids querying the database for users if there are still syntax
          # errors in the file or we do not have a project
          return if !project || file.errors.present?

          entries.each do |entry|
            references = Gitlab::CodeOwners::ReferenceExtractor.new(entry.owner_line)

            funnel.each do |filter|
              bubble_errors_for(entry.line_number, references, filter)
            end
          end
        end

        private

        attr_reader :project, :file, :max_references_limit, :entries

        # Filters validate an individual step in the elibility requirements
        # list for a code owners.
        #
        # In the first validation step we find all of the users and groups that
        # are accessible by the project.
        #
        # Once we've found these, we pass all the usernames, emails, and users
        # to the second filter to find all the users which have permission to
        # approve an MR.
        #
        # We also pass all of the groups from the first step to a different
        # filter to find all the groups that have a max_role value high enough
        # to allow users within the group to approve an MR.
        #
        # We then pass all of the users within these groups to another filter
        # to ensure these groups have at least 1 direct member that can approve
        # an MR within the project.
        #
        # Once we've collected all of these owners we apply all of the errors
        # in one loop so we aren't iterating over all of the entries for each
        # validator.
        def funnel
          [
            accessible_owners_filter,
            eligible_approvers_filter,
            qualified_groups_filter,
            eligible_approver_groups_filter
          ]
        end
        strong_memoize_attr :funnel

        def accessible_owners_filter
          owners = entries.map(&:owner_line)
          references = ReferenceExtractor.new(owners)
          names = references.names.first(max_references_limit)
          remaining_limit = max_references_limit - names.length
          emails = remaining_limit > 0 ? references.emails.first(remaining_limit) : []
          AccessibleOwnersFilter.new(project, names: names, emails: emails)
        end
        strong_memoize_attr :accessible_owners_filter

        def eligible_approvers_filter
          upstream = accessible_owners_filter
          EligibleApproversFilter.new(
            project,
            users: upstream.output_users,
            usernames: upstream.valid_usernames,
            emails: upstream.valid_emails
          )
        end
        strong_memoize_attr :eligible_approvers_filter

        def qualified_groups_filter
          upstream = accessible_owners_filter
          QualifiedGroupsFilter.new(
            project,
            groups: upstream.output_groups,
            group_names: upstream.valid_group_names
          )
        end
        strong_memoize_attr :qualified_groups_filter

        def eligible_approver_groups_filter
          upstream = qualified_groups_filter
          EligibleApproverGroupsFilter.new(
            project,
            groups: upstream.output_groups,
            group_names: upstream.valid_group_names
          )
        end

        def bubble_errors_for(line_number, references, filter)
          return if filter.valid_entry?(references)

          file.errors.add(filter.error_message, line_number)
        end
      end
    end
  end
end
