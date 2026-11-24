# frozen_string_literal: true

# rubocop:disable CodeReuse/ActiveRecord -- the resolver builds the candidate query from the policy_scope document
module Govern
  module PolicyEngine
    # Turns the policy_scope document of a policy into the candidate projects
    # for evaluation. Over-approximates, because the engine makes the real
    # scope decision from the same document compiled to Rego.
    class ScopedProjectsResolver
      include Gitlab::Utils::StrongMemoize

      BATCH_SIZE = 100

      PROJECTS = 'projects'
      GROUPS = 'groups'
      COMPLIANCE_FRAMEWORKS = 'compliance_frameworks'
      INCLUDING = 'including'
      EXCLUDING = 'excluding'
      ARCHIVED = 'archived'
      PERSONAL = 'personal'

      def initialize(policy)
        @policy = policy
        @scope = policy.policy_scope.try(:deep_stringify_keys) || {}
      end

      def each_candidate_batch(of: BATCH_SIZE)
        inclusion_arms.each do |arm|
          arm.each_batch(of: of) do |batch|
            yield excluded(batch)
          end
        end
      end

      private

      attr_reader :policy, :scope

      def base_relation
        relation = Project.in_organization(policy.organization_id)
        return relation unless policy.namespace_id

        subtree = Namespace.find_by_id(policy.namespace_id)&.self_and_descendant_ids
        relation.where(namespace_id: subtree || [])
      end

      # One arm per inclusion dimension, each batched on its own. A union of the
      # arms hides projects.id from the keyset boundary, so every batch re-reads
      # the whole compliance framework arm.
      #
      # A later arm subtracts the earlier ones, so a project that two dimensions
      # name is still yielded once. Every subtraction reads projects.id, which
      # the arm is already ordered by. The group arm therefore comes last:
      # subtracting the framework arm from it on namespace_id instead drops the
      # boundary query off its index and onto a range scan.
      def inclusion_arms
        project_ids = criterion(PROJECTS, INCLUDING).ids
        group_ids = criterion(GROUPS, INCLUDING).ids
        framework_ids = ScopeCriterion.from(scope[COMPLIANCE_FRAMEWORKS]).ids

        return [base_relation] if project_ids.empty? && group_ids.empty? && framework_ids.empty?

        arms = []

        arms << base_relation.id_in(project_ids) if project_ids.any?

        if framework_ids.any?
          arm = base_relation.where(id: framework_project_ids(framework_ids))
          arms << (project_ids.any? ? arm.id_not_in(project_ids) : arm)
        end

        if group_ids.any?
          arm = base_relation.where(namespace_id: descendant_namespace_ids(group_ids))
          arm = arm.id_not_in(project_ids) if project_ids.any?
          arm = arm.where.not(id: framework_project_ids(framework_ids)) if framework_ids.any?
          arms << arm
        end

        arms
      end

      def framework_project_ids(framework_ids)
        ComplianceManagement::ComplianceFramework::ProjectSettings
          .where(framework_id: framework_ids).select(:project_id)
      end

      def excluded(relation)
        excluded_projects = criterion(PROJECTS, EXCLUDING)
        project_ids = excluded_projects.ids
        relation = relation.id_not_in(project_ids) if project_ids.any?

        relation = relation.where.not(namespace_id: excluded_namespace_ids) if excluded_namespace_ids

        relation = relation.non_archived if excluded_projects.includes_type?(ARCHIVED)
        relation = relation.where.not(personal_namespace_subquery.exists) if
          excluded_projects.includes_type?(PERSONAL)

        relation
      end

      def criterion(dimension, direction)
        lists = scope[dimension]

        ScopeCriterion.from(lists.is_a?(Hash) ? lists[direction] : nil)
      end

      # Memoized because each_candidate_batch applies the exclusions once per
      # batch.
      def excluded_namespace_ids
        group_ids = criterion(GROUPS, EXCLUDING).ids

        descendant_namespace_ids(group_ids) if group_ids.any?
      end
      strong_memoize_attr :excluded_namespace_ids

      def descendant_namespace_ids(group_ids)
        subtrees = Group.id_in(group_ids).map(&:self_and_descendant_ids)
        return Namespace.none if subtrees.empty?

        Namespace.from_union(subtrees)
      end

      def personal_namespace_subquery
        namespace_table = Namespace.arel_table

        namespace_table
          .project(1) # SELECT 1
          .where(namespace_table[:id].eq(Project.arel_table[:namespace_id]))
          .where(namespace_table[:type].eq(Namespaces::UserNamespace.sti_name))
      end
    end
  end
end
# rubocop:enable CodeReuse/ActiveRecord
