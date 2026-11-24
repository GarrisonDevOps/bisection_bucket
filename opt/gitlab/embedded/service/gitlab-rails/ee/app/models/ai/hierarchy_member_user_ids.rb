# frozen_string_literal: true

module Ai
  class HierarchyMemberUserIds
    NAMESPACE_BATCH_SIZE = 100
    MEMBER_BATCH_SIZE = 1_000

    def initialize(group)
      @group = group
    end

    # Yields the user IDs of members of the group, its subgroups and their projects, skipping
    # access requests and pending invites. Each batch has at most MEMBER_BATCH_SIZE unique IDs,
    # and a user can appear in more than one batch.
    #
    # @yieldparam user_ids [Array<Integer>]
    # @return [void]
    def each_user_ids_batch(&block)
      cursor = { current_id: group.id, depth: [group.id] }
      namespaces = ::Gitlab::Database::NamespaceEachBatch.new(namespace_class: ::Namespace, cursor: cursor)

      namespaces.each_batch(of: NAMESPACE_BATCH_SIZE) do |namespace_ids|
        next if yielded_as_single_batch?(members(::Member.where(member_namespace_id: namespace_ids)), &block)

        each_user_ids_batch_by_source(namespace_ids, &block)
      end

      nil
    end

    private

    attr_reader :group

    # The member_namespace_id index sorts by type and requested_at before id, so batching a
    # slice by id sorts every member in it. Each source's own index is already in id order.
    def each_user_ids_batch_by_source(namespace_ids, &block)
      source_members(namespace_ids).each do |relation|
        source = members(relation)
        next if yielded_as_single_batch?(source, &block)

        source.each_batch(of: MEMBER_BATCH_SIZE) do |batch|
          yield_user_ids(batch.limit(MEMBER_BATCH_SIZE).pluck(:user_id), &block)
        end
      end
    end

    def yielded_as_single_batch?(relation, &block)
      user_ids = relation.limit(MEMBER_BATCH_SIZE + 1).pluck(:user_id)
      return false if user_ids.size > MEMBER_BATCH_SIZE

      yield_user_ids(user_ids, &block)
      true
    end

    def source_members(namespace_ids)
      group_ids = ::Group.id_in(namespace_ids).limit(namespace_ids.size).pluck(:id)
      project_ids = ::Project.by_project_namespace(namespace_ids).limit(namespace_ids.size).pluck(:id)

      group_ids.map { |id| ::GroupMember.where(source_id: id) } +
        project_ids.map { |id| ::ProjectMember.where(source_id: id) }
    end

    def members(relation)
      relation.non_request.non_invite
    end

    def yield_user_ids(user_ids)
      user_ids = user_ids.uniq
      yield user_ids if user_ids.present?
    end
  end
end
