# frozen_string_literal: true

module Ai
  module Catalog
    module ItemConsumers
      module EventsTracking
        include Gitlab::InternalEventsTracking

        def track_item_consumer_event(item_consumer, event_name, flow_trigger)
          event_properties = Ai::Catalog::Tracking::EventPropertiesBuilder
            .new(item: item_consumer.item, version: item_consumer.pinned_version)
            .to_h

          track_internal_event(
            event_name,
            user: current_user,
            project: item_consumer.project,
            namespace: item_consumer.group,
            additional_properties: event_properties.merge(
              label: item_consumer.enabled.to_s,
              property: item_consumer.locked.to_s,
              triggers: triggers(flow_trigger)
            ).compact
          )
        end

        # Emits item-consumer audit events with explicit actor and provenance overrides.
        #
        # @param item_consumer [Ai::Catalog::ItemConsumer] changed consumer
        # @param event_type [String] audit event name
        # @param author [User, Gitlab::Audit::UnauthenticatedAuthor, nil] actor recorded by the audit framework
        # @param additional_details [Hash, nil] non-sensitive provenance merged into each audit event
        # @return [Array] result of iterating through the generated audit messages
        # @note This writes audit events only; it does not alter the consumer. Defaults preserve the
        #   existing caller actor. Automated inherited provisioning can use a system author without
        #   changing analytics attribution or membership provenance.
        def send_audit_events(item_consumer, event_type, author: current_user, additional_details: nil)
          messages = audit_event_messages(event_type, item_consumer)
          scope = item_consumer.project || item_consumer.group

          messages.each do |message|
            audit_context = {
              name: event_type,
              author: author,
              scope: scope,
              target: item_consumer.item,
              target_details: "#{item_consumer.item.name} (ID: #{item_consumer.item.id})",
              message: message
            }
            audit_context[:additional_details] = additional_details if additional_details.present?

            ::Gitlab::Audit::Auditor.audit(audit_context)
          end
        end

        private

        def audit_event_messages(event_type, item_consumer)
          item = item_consumer.item
          service_class = "::Ai::Catalog::#{item.item_type.to_s.camelize.pluralize}::" \
            "AuditEventMessageService".safe_constantize

          return [] if service_class.nil?

          scope_type = if item_consumer.project_id.present?
                         'project'
                       elsif item_consumer.group_id.present?
                         'group'
                       end

          params = { scope: scope_type, item_consumer: item_consumer }.compact

          service_class.new(event_type, item, params).messages
        end

        def triggers(flow_trigger)
          event_type_ids = flow_trigger.try(:event_types)

          return unless event_type_ids

          event_type_ids.filter_map { |id| FlowTrigger::EVENT_TYPES_BY_ID[id].to_s }.join(
            Tracking::EventPropertiesBuilder::LIST_SEPARATOR
          )
        end
      end
    end
  end
end
