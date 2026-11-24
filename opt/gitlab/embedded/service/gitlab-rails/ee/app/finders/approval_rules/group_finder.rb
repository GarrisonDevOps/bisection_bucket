# frozen_string_literal: true

# For caching group related queries relative to current_user
module ApprovalRules
  class GroupFinder
    include Gitlab::Utils::StrongMemoize

    attr_reader :rule, :current_user

    def initialize(rule, user)
      @rule = rule
      @current_user = user
    end

    def visible_groups
      strong_memoize(:visible_groups) do
        groups.accessible_to_user(current_user)
      end
    end

    def hidden_groups
      @hidden_groups ||= groups.id_not_in((visible_groups.map(&:id) + project_group_ids).uniq)
    end

    def contains_hidden_groups?
      # Any-approver rules use Group.none to guarantee an empty set, while the
      # approval-state path preloads groups. Both avoid queries and policy checks.
      return false if groups.null_relation? || (groups.loaded? && groups.empty?)

      hidden_groups.loaded? ? hidden_groups.present? : hidden_groups.exists?
    end

    private

    def project_group_ids
      project = rule.rule_project

      return [] unless project

      return [] unless current_user && Feature.enabled?(:show_private_groups_as_approvers, project) &&
        Ability.allowed?(current_user, :read_project, project)

      Gitlab::SafeRequestStore.fetch([:approval_rules_invited_group_ids, project.id]) do
        project.invited_groups.pluck_primary_key
      end
    end

    def groups
      strong_memoize(:groups) do
        rule.any_approver? ? Group.none : rule.groups
      end
    end
  end
end
