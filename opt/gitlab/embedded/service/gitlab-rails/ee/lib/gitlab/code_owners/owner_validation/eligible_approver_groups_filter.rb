# frozen_string_literal: true

module Gitlab
  module CodeOwners
    module OwnerValidation
      class EligibleApproverGroupsFilter
        include ::Gitlab::Utils::StrongMemoize

        def initialize(project, groups:, group_names:)
          @project = project
          @input_groups = groups
          @input_group_names = group_names
        end

        def error_message
          :group_without_eligible_approvers
        end

        def output_groups
          result = if Feature.enabled?(:optimize_codeowners_group_validation, project)
                     input_groups.select { |group| groups_with_eligible_approvers.include?(group.id) }
                   else
                     preload_associations
                     input_groups.select { |group| any_approvers?(group) }
                   end

          log_user_ids_loaded

          result
        end
        strong_memoize_attr :output_groups

        def valid_group_names
          output_groups.map(&:full_path)
        end
        strong_memoize_attr :valid_group_names

        def invalid_group_names
          input_group_names - valid_group_names
        end
        strong_memoize_attr :invalid_group_names

        def valid_entry?(references)
          !references.names.intersect?(invalid_group_names)
        end

        private

        attr_reader :project, :input_groups, :input_group_names

        # rubocop:disable CodeReuse/ActiveRecord -- Optimized query for performance
        def eligible_project_users_subquery
          banned_users_subquery = Namespaces::NamespaceBan
            .where('namespace_bans.user_id = users.id')
            .where(namespace: project.root_namespace)

          project.authorized_users
                .where(project_authorizations: { access_level: Gitlab::Access::DEVELOPER..Gitlab::Access::ADMIN })
                .where_not_exists(banned_users_subquery)
                .select(:user_id)
        end
        strong_memoize_attr :eligible_project_users_subquery

        def groups_with_eligible_approvers
          GroupMember
            .active_without_invites_and_requests
            .with_source(input_groups)
            .where(user_id: eligible_project_users_subquery)
            .distinct
            .pluck(:source_id)
            .to_set
        end
        # rubocop:enable CodeReuse/ActiveRecord
        strong_memoize_attr :groups_with_eligible_approvers

        # log user ID count processed per validation
        def log_user_ids_loaded
          return unless Feature.enabled?(:log_codeowners_validation_user_ids, project)

          Gitlab::AppLogger.info(
            message: "CODEOWNERS group validation user IDs loaded",
            project_id: project.id,
            eligible_user_ids_count: eligible_project_users_subquery.count,
            groups_count: input_groups.size
          )
        end

        # Legacy implementation for when feature flag is disabled
        def preload_associations
          ActiveRecord::Associations::Preloader.new(records: input_groups, associations: [users: :namespace_bans]).call
          user_ids = input_groups.flat_map(&:user_ids).uniq
          project.team.max_member_access_for_user_ids(user_ids)
        end

        def any_approvers?(group)
          group.users.any? { |user| Ability.allowed?(user, :update_merge_request, project) }
        end
      end
    end
  end
end
