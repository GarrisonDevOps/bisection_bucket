# frozen_string_literal: true

module Authz
  module ProjectAuthorizations
    # Turns a namespace or share event into the project and membership events it implies, so one large target
    # becomes many small ones that any worker can take. It only queues events, so it runs whether or not
    # those are computed yet.
    #
    # A namespace change moves a reach, so it expands into all-user project events: a membership event only
    # recalculates the reach as it is now and would miss users who lost access through the old one.
    class ExpandService
      BATCH_SIZE = 1_000

      # @param lease [RefreshEvent::Lease] a lease of one of RefreshEvent::EXPANSION_TYPES
      def initialize(lease)
        @lease = lease
      end

      # Queues the expanded events in batches, each in a transaction that also advances the lease's cursor past
      # it, so no transaction grows with the expansion. A worker that crashes or loses its lease leaves the cursor
      # at its last committed batch, and whoever takes the events over resumes there.
      #
      # @return [ServiceResponse] payload has :events, the number queued
      # @raise [RefreshEvent::LeaseLostError]
      def execute
        type, ids = read_from_primary { expansion }
        ids = ids.select { |id| id > lease.cursor } if lease.cursor

        ids.sort.each_slice(BATCH_SIZE).reduce(lease) do |current, batch|
          RefreshEvent.transaction do
            # Advancing first stops a worker that lost its lease before it inserts anything.
            advanced = RefreshEvent.advance(current, cursor: batch.last)
            RefreshEvent.enqueue(type, targets(type, batch), first_queued_at: lease.first_queued_at)
            advanced
          end
        end
        RefreshEvent.finish(lease)

        ServiceResponse.success(payload: { events: ids.size })
      end

      private

      attr_reader :lease

      # The worker's sticky consistency only waits for the replica to reach the point cron queued the job, and the
      # change behind this event can be newer. Uncached, since the reads decide what's queued.
      def read_from_primary(&)
        ::Gitlab::Database::LoadBalancing::SessionMap.current(::ApplicationRecord.load_balancer).use_primary do
          ::ApplicationRecord.uncached(&)
        end
      end

      # The IDs to queue: projects, or the users of membership events. Read whole, once per lease, since a group
      # move's IDs come from a union over its subtree that can't resume cheaply; the largest is 201k IDs.
      # rubocop:disable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit -- read once, queued in batches
      def expansion
        case lease.target_type
        when :namespace_subtree
          [:project, subtree_project_ids]
        when :namespace_project_group_links
          # The share lock only decides whether the namespace's own projects' shares grant access.
          [:project, ::ProjectGroupLink.where(project_id: ::Project.in_namespace(lease.target_id).select(:id))
            .distinct.pluck(:project_id)]
        when :group_group_link
          # A share grants the invited group's (the target's) direct members access to the shared group's (the
          # scope's) reach.
          [:user_in_group, ::GroupMember.of_groups(lease.target_id).authorizable.distinct.pluck(:user_id)]
        else
          raise ArgumentError, "#{lease.target_type} events are not expanded"
        end
      end

      # A group move changes access to everything under it and everything shared with it. A personal
      # namespace's owner change only reaches its own projects.
      def subtree_project_ids
        namespace = ::Namespace.find_by_id(lease.target_id)
        return [] unless namespace
        return ::Project.in_namespace(namespace.id).ids unless namespace.is_a?(::Group)

        ::Groups::ProjectsRequiringAuthorizationsRefresh::OnTransferFinder.new(namespace).execute
      end
      # rubocop:enable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit

      def targets(type, ids)
        type == :user_in_group ? ids.map { |user_id| [user_id, lease.scope_id] } : ids
      end
    end
  end
end
