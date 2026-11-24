# frozen_string_literal: true

module Ai
  module CloudEventsFlowTriggerWorker
    extend ActiveSupport::Concern
    include Gitlab::EventStore::Subscriber

    included do
      data_consistency :sticky
      feature_category :dap_triggers
    end

    def handle_event(cloud_event)
      unless cloud_event.is_a?(self.class.cloud_event_class)
        logger.warn(structured_payload(message: 'Unexpected cloud event type.',
          expected: self.class.cloud_event_class.name,
          got: cloud_event.class.name))
        return
      end

      resource, container = find_resource_and_container(cloud_event)
      return unless resource

      return unless feature_enabled?(container)

      chaining = chaining_enabled?(cloud_event, container)

      # Until chaining is bounded, flows must not start other flows through events.
      # See https://gitlab.com/gitlab-org/gitlab/-/work_items/630476
      if !chaining && originated_from_flow?(cloud_event)
        log_flow_originated_skip(cloud_event, 'Event caused by a flow, skipping flow triggers.')
        return
      end

      current_user = resolve_current_user(cloud_event, resource)

      unless current_user
        logger.info(structured_payload(message: 'User not found.',
          gitlab_user_id: cloud_event.data[:gitlab_user_id]))
        return
      end

      parent_workflow = nil
      if chaining
        parent_workflow = resolve_parent_workflow(cloud_event, resource)

        unless parent_workflow
          log_flow_originated_skip(cloud_event,
            'Event caused by a flow without an authorized parent workflow, skipping flow triggers.')
          return
        end
      end

      return unless flow_triggers_registered?(container)
      return unless passes_event_checks?(cloud_event, resource)

      execute_flow_triggers(resource, container, current_user, cloud_event, parent_workflow)
    end

    private

    # The subscription guard keeps projects without triggers out of the queue. Repeating the
    # check here keeps the event checks (an approval state, a reviewer lookup) from being paid
    # for an event that reached the queue without it.
    def flow_triggers_registered?(container)
      ::Ai::FlowTrigger.registered_for?(container.id, self.class.event_type)
    end

    # Subclasses must implement. Returns [resource, container] or nil if not found.
    def find_resource_and_container(_cloud_event)
      raise NotImplementedError, "#{self.class} must implement #find_resource_and_container"
    end

    # Override in subclasses to gate on a feature flag.
    # Defaults to true so workers can remove the override after full rollout.
    def feature_enabled?(_container)
      true
    end

    def originated_from_flow?(cloud_event)
      cloud_event.data[:gitlab_composite_actor_id].present?
    end

    def chaining_enabled?(cloud_event, container)
      cloud_event.data[:gitlab_composite_actor_id].present? &&
        Feature.enabled?(:ai_flow_trigger_chaining, container.root_ancestor)
    end

    def log_flow_originated_skip(cloud_event, message)
      logger.info(structured_payload(message: message,
        reason: :non_human_trigger_not_permitted,
        gitlab_composite_actor_id: cloud_event.data[:gitlab_composite_actor_id],
        Labkit::Fields::DUO_WORKFLOW_ID => cloud_event.data[:gitlab_duo_workflow_id]))
    end

    # Override in subclasses to add event specific pre-checks.
    def passes_event_checks?(_cloud_event, _resource)
      true
    end

    # Override in subclasses for events that do not carry the acting user.
    def resolve_current_user(cloud_event, _resource)
      cloud_event.current_user
    end

    # Override in subclasses for flows that publish the event without their composite identity.
    def resolve_parent_workflow(cloud_event, _resource)
      # The event's user is the one whose flow caused it. `current_user` can differ (the merged-MR
      # worker runs as the author), and a chained run acts for the chain's root human anyway.
      ::Ai::FlowTriggers::CallerContext.authorized_parent_workflow(
        cloud_event.data[:gitlab_duo_workflow_id], cloud_event.current_user)
    end

    # Override in subclasses to add flow trigger specific pre-checks.
    def passes_trigger_checks?(_flow_trigger, _cloud_event, _resource, _parent_workflow)
      true
    end

    # Override in subclasses to act on the response of RunService#execute, for example when the run did not start.
    def after_flow_trigger_run(_flow_trigger, _resource, _response); end

    # Override in subclasses to pass event specific params to RunService#execute.
    def additional_run_params(_cloud_event, _resource)
      {}
    end

    # Override in subclasses to expose event payload and resource fields to FilterEvaluator rules.
    def filter_data_extras(_cloud_event, _resource)
      {}
    end

    def execute_flow_triggers(resource, container, current_user, cloud_event, parent_workflow)
      event_type = self.class.event_type
      action = self.class.respond_to?(:action) ? self.class.action : nil

      flow_triggers = ::Ai::FlowTrigger.applicable_to_project(container, triggered_on: event_type)

      # Some workers and their event_type define an action (e.g. event_type: merge_request,
      # action: 'approved') while others might not. It is set last so that an override of
      # filter_data_extras can never replace it.
      filter_data = filter_data_extras(cloud_event, resource).dup
      filter_data['action'] = action if action

      flow_triggers.each do |trigger|
        next unless ::Ai::FlowTriggers::FilterEvaluator.new(
          flow_trigger: trigger,
          hook_scope: event_type,
          data: filter_data
        ).allowed?

        next unless passes_trigger_checks?(trigger, cloud_event, resource, parent_workflow)

        run_params = { input: resource.iid.to_s, event: event_type }
        run_params[:action] = action if action
        run_params.merge!(additional_run_params(cloud_event, resource))

        response = begin
          ::Ai::FlowTriggers::RunService.new(
            project: container,
            current_user: current_user,
            flow_trigger: trigger,
            resource: resource,
            parent_workflow: parent_workflow
          ).execute(run_params)
        rescue StandardError => error
          # A run that raises is a failed run too, so `after_flow_trigger_run` gets an error response for it.
          track_flow_trigger_error(error, trigger, resource, container)
          ServiceResponse.error(message: 'Flow trigger run raised an error.')
        end

        after_flow_trigger_run(trigger, resource, response)
      rescue StandardError => error
        track_flow_trigger_error(error, trigger, resource, container)
      end
    end

    def track_flow_trigger_error(error, trigger, resource, container)
      Gitlab::ErrorTracking.track_exception(error,
        flow_trigger_id: trigger.id,
        resource_id: resource.id,
        container_id: container.id
      )
    end
  end
end
