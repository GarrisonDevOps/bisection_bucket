# frozen_string_literal: true

module Namespaces
  module Export
    class MembershipCollector
      attr_reader :result, :target_group_ancestor_ids, :members, :target_group, :current_user

      def initialize(target_group, current_user)
        @result = []
        @members = { projects: {}, groups: {} }

        @current_user = current_user
        @target_group = target_group
        @target_group_ancestor_ids = target_group.ancestor_ids
      end

      def execute
        cursor = { current_id: target_group.id, depth: [target_group.id] }
        iterator = Gitlab::Database::NamespaceEachBatch.new(namespace_class: Group, cursor: cursor)

        log_progress("Collection of memberships starting")

        iterator.each_batch(of: 100) do |ids|
          groups = Group.id_in(ids).in_order_of(:id, ids)

          groups.each do |group|
            log_progress("Detailed export started for a group", group)
            process_group(group)
            log_progress("Detailed export started for group projects", group)
            process_group_projects(group)
            log_progress("Detailed export ended for a group", group)
          end
        end

        log_progress("Collection of memberships ended")

        order
      end

      private

      def log_progress(message, group = nil)
        Gitlab::AppLogger.info(
          class: self.class,
          message: message,
          group: group&.id
        )
      end

      def order
        result.sort_by do |member|
          [member.membershipable_class, member.membershipable_id, member.membership_type, member.username || '']
        end
      end

      def process_group(group)
        group_memberships = memberships_for_group(group)
        group_parent = group.parent_id unless target_group == group

        update_parent_groups(group_parent) unless group == target_group

        all_group_members = if target_group == group
                              group_memberships
                            else
                              combine_memberships(group, group_memberships, group_parent)
                            end

        result.concat(transform_data(all_group_members, group))

        target_group_ancestor_ids << group.id
        members[:groups][group.id] = all_group_members
      end

      def process_group_projects(group)
        group.projects.with_group.each_batch(of: 100) do |projects|
          projects.each do |project|
            process_project(project)
          end
        end
      end

      def process_project(project)
        project_memberships = memberships_for_project(project)
        all_project_members = combine_memberships(project, project_memberships, project.group.id)

        result.concat(transform_data(all_project_members, project))
      end

      def combine_memberships(entity, memberships, parent)
        MembersTypeCombinator.new(entity)
                                  .execute(memberships.to_a, members[:groups][parent])
      end

      def memberships_for_group(group)
        # for all groups we retrieve direct and shared members, inherited will be calculated from the ancestors
        relations = [:direct, :shared_from_groups]

        # for root group we have to retrieve also inherited members as there is no ancestor to calculate them from
        relations << :inherited if group == target_group

        GroupMembersFinder.new(group, current_user).execute(include_relations: relations)
          .including_source.including_user
      end

      def memberships_for_project(project)
        MembersFinder.new(project, current_user).execute(include_relations: [:direct])
          .including_source.including_user
      end

      def update_parent_groups(group_parent)
        # no need to update when we don't have any ancestors for the group parent
        return if target_group_ancestor_ids.empty?

        # no need to update when the last ancestor id is the current group parent
        return if group_parent == target_group_ancestor_ids.last

        parent_index = target_group_ancestor_ids.find_index(group_parent)
        count_to_remove = target_group_ancestor_ids.size - parent_index - 1
        target_group_ancestor_ids.pop(count_to_remove)
      end

      def transform_data(memberships, source)
        return [] unless memberships

        memberships.map do |member|
          ::Namespaces::Export::Member.new(member, source, target_group_ancestor_ids)
        end
      end
    end
  end
end
