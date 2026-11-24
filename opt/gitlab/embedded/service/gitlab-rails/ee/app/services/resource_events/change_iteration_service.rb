# frozen_string_literal: true

module ResourceEvents
  class ChangeIterationService < ::ResourceEvents::BaseChangeTimeboxService
    attr_reader :iteration, :old_iteration, :automated, :triggered_by_work_item

    def initialize(resource, user, old_iteration:, automated: false, triggered_by_work_item: nil)
      super(resource, user)

      @resource = resource
      @user = user
      @iteration = resource&.iteration
      @old_iteration = old_iteration
      @automated = automated
      @triggered_by_work_item = triggered_by_work_item
    end

    def build_resource_args
      action, iteration_for_event = if iteration.blank?
                                      [:remove, old_iteration]
                                    else
                                      [:add, iteration]
                                    end

      return if iteration_for_event.blank?

      super.merge({
        action: ResourceTimeboxEvent.actions[action],
        iteration_id: iteration_for_event.id,
        automated: automated,
        triggered_by_id: triggered_by_work_item&.id,
        namespace_id: iteration_for_event.group_id
      })
    end

    private

    def track_event
      return unless resource.is_a?(WorkItem)

      Gitlab::UsageDataCounters::WorkItemActivityUniqueCounter.track_work_item_iteration_changed_action(author: user)
    end

    def create_event
      create_args = build_resource_args

      ResourceIterationEvent.create(create_args) if create_args.present?
    end
  end
end
