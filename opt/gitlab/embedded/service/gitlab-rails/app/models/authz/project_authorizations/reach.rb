# frozen_string_literal: true

module Authz
  module ProjectAuthorizations
    # The projects whose access can change when a user's membership in one of the groups changes:
    # projects in each group's subtree, projects shared with a group in that subtree, and the same for every
    # group the groups are invited into, because a group's direct members get access through those shares.
    #
    # Access to any other project can't depend on the membership. Extra projects only cost work, so share
    # locks aren't checked here.
    class Reach
      BATCH_SIZE = 1_000

      # Every project one user can have access to, for repairing that user: their current rows, the reach
      # of all their group memberships, their personal projects and their project memberships. The current
      # rows cover stale grants that no reach explains.
      #
      # @param user_id [Integer]
      # @return [Array<Integer>] project IDs
      # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- one user's memberships and projects, read once per repair
      def self.for_user(user_id)
        memberships = ::Member.where(user_id: user_id).non_request.pluck(:source_type, :source_id)
        group_ids, project_ids = memberships.partition { |type, _| type == ::GroupMember::SOURCE_TYPE }
          .map { |pairs| pairs.map(&:last) }
        personal = ::Project.joins(:namespace)
          .where(namespaces: { type: ::Namespaces::UserNamespace.sti_name, owner_id: user_id }).ids

        (::ProjectAuthorization.for_user(user_id).pluck(:project_id) + new(group_ids).project_ids +
          personal + project_ids).uniq
      end
      # rubocop:enable Database/AvoidUsingPluckWithoutLimit

      # @param group_ids [Array<Integer>]
      def initialize(group_ids)
        @group_ids = group_ids
      end

      # @return [Array<Integer>] project IDs
      # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- bounded by the groups' reach
      def project_ids
        roots = group_ids.each_slice(BATCH_SIZE).flat_map do |ids|
          ids + ::GroupGroupLink.where(shared_with_group_id: ids).pluck(:shared_group_id)
        end

        # The subtree's IDs are read first: as a subquery, the planner can scan all of projects for it.
        subtree_ids = top_level(roots.uniq).each_slice(BATCH_SIZE).flat_map { |ids| subtree_group_ids(ids) }

        subtree_ids.uniq.each_slice(BATCH_SIZE).flat_map do |ids|
          ::Project.where(namespace_id: ids).pluck(:id) + ::ProjectGroupLink.where(group_id: ids).pluck(:project_id)
        end.uniq
      end
      # rubocop:enable Database/AvoidUsingPluckWithoutLimit

      private

      attr_reader :group_ids

      # The groups not under another of the groups, whose subtrees then don't overlap. The descendants scopes
      # do this in SQL by comparing every pair, which took 3 to 4 s for a user in 30,000 groups.
      def top_level(ids)
        paths = ids.each_slice(BATCH_SIZE).flat_map do |batch|
          ::Group.id_in(batch).pluck(:traversal_ids) # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- bounded by the batch
        end
        given = paths.to_set(&:last)

        paths.reject { |path| path[0...-1].any? { |ancestor| given.include?(ancestor) } }.map(&:last)
      end

      # Every group in the subtrees, read as one range of the traversal_ids index per root.
      def subtree_group_ids(root_ids)
        ::Group.joins(<<~SQL.squish).where(root: { id: root_ids }).pluck(:id) # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- bounded by the subtrees
          INNER JOIN namespaces AS root ON namespaces.traversal_ids >= root.traversal_ids
            AND namespaces.traversal_ids < next_traversal_ids_sibling(root.traversal_ids)
        SQL
      end
    end
  end
end
