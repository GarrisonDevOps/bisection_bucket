# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class FetchPolicyApproversService
      include BaseServiceUtility
      include ::GitlabSubscriptions::SubscriptionHelper

      def initialize(policy:, container:, current_user:)
        @policy = policy
        @current_user = current_user
        @container = container
      end

      def execute
        actions = required_approvals(policy)

        if actions.nil? || actions.empty?
          return success({ users: [], groups: [], all_groups: [], roles: [],
approvers: [] })
        end

        approvers = actions.map do |action|
          approver_groups = group_approvers(action)

          {
            users: user_approvers(action),
            groups: approver_groups[:visible],
            all_groups: approver_groups[:all],
            roles: role_approvers(action),
            custom_roles: custom_roles(action)
          }
        end

        first_approver = approvers&.first

        success({
          users: first_approver[:users],
          groups: first_approver[:groups],
          all_groups: first_approver[:all_groups],
          roles: first_approver[:roles],
          custom_roles: first_approver[:custom_roles],
          approvers: approvers
        })
      end

      private

      attr_reader :policy, :container, :current_user

      def required_approvals(policy)
        policy&.dig(:actions)&.select { |action| action&.fetch(:type) == Security::ScanResultPolicy::REQUIRE_APPROVAL }
      end

      def user_approvers(action)
        return [] unless action[:user_approvers] || action[:user_approvers_ids]

        user_names, user_ids = approvers_within_limit(action[:user_approvers], action[:user_approvers_ids])
        case container
        when Project
          container.team.users.by_ids_or_usernames(user_ids, user_names)
        when Group
          authorizable_users_in_group_hierarchy_by_ids_or_usernames(user_ids, user_names)
        else
          []
        end
      end

      # rubocop: disable CodeReuse/ActiveRecord
      def authorizable_users_in_group_hierarchy_by_ids_or_usernames(user_ids, user_names)
        User.by_ids_or_usernames(user_ids, user_names)
          .id_in(container.authorizable_members_with_parents.pluck(:user_id))
      end
      # rubocop: enable CodeReuse/ActiveRecord

      def group_approvers(action)
        return { visible: [], all: [] } unless action[:group_approvers] || action[:group_approvers_ids]

        group_paths, group_ids = approvers_within_limit(action[:group_approvers], action[:group_approvers_ids])

        service = Security::ApprovalGroupsFinder.new(group_ids: group_ids,
          group_paths: group_paths,
          user: current_user,
          container: container,
          search_globally: search_groups_globally?)

        visible = service.execute
        all = service.execute(include_inaccessible: true)

        { visible: visible, all: all }
      end

      def custom_roles(action)
        custom_role_ids = action[:role_approvers]&.grep(Integer)

        return [] unless custom_role_ids.present?

        if gitlab_com_subscription?
          container.root_ancestor.member_roles.id_in(custom_role_ids)
        else
          # member_roles shards by namespace_id or organization_id; for_instance rows (no
          # namespace) are exactly the org-sharded ones, so they must be scoped explicitly.
          roles = MemberRole.for_instance.id_in(custom_role_ids)
          container ? roles.in_organization(container.organization_id) : roles
        end
      end

      def role_approvers(action)
        action[:role_approvers].to_a & Security::ScanResultPolicy::ALLOWED_ROLES
      end

      def search_groups_globally?
        Gitlab::CurrentSettings.security_policy_global_group_approvers_enabled?
      end

      def approvers_within_limit(names, ids)
        filtered_names = names&.first(Security::ScanResultPolicy::APPROVERS_LIMIT) || []
        filtered_ids = []

        if filtered_names.count < Security::ScanResultPolicy::APPROVERS_LIMIT
          filtered_ids = ids&.first(Security::ScanResultPolicy::APPROVERS_LIMIT - filtered_names.count)
        end

        [filtered_names, filtered_ids]
      end
    end
  end
end
