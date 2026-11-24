# frozen_string_literal: true

module Issuables
  class ResourceIterationEventFinder
    def initialize(current_user, eventable)
      @current_user = current_user
      @eventable = eventable
    end

    # Returns the ResourceIterationEvents of the eventable
    # visible to the user.
    #
    # @return ResourceIterationEvent::ActiveRecord_AssociationRelation
    def execute
      eventable.resource_iteration_events.with_api_entity_associations
        .where(iteration_id: readable_iteration_ids) # rubocop: disable CodeReuse/ActiveRecord -- authorization query specific to this finder
    end

    private

    attr_reader :current_user, :eventable

    def readable_iteration_ids
      events_iterations.select { |iteration| group_availabilities[iteration.group_id] }.map(&:id)
    end

    # rubocop: disable CodeReuse/ActiveRecord -- authorization query specific to this finder
    def events_iterations
      @events_iterations ||= Iteration.id_in(eventable.resource_iteration_events.select(:iteration_id))
                               .preload(:group)
    end
    # rubocop: enable CodeReuse/ActiveRecord

    def group_availabilities
      @group_availabilities ||= events_iterations.map(&:group).uniq.to_h do |group|
        [group.id, Ability.allowed?(current_user, :read_iteration, group)]
      end
    end
  end
end
