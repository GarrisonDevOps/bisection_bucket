# frozen_string_literal: true

module EE
  module Gitlab
    module Issuable
      module Clone
        module CopyResourceEventsService
          extend ::Gitlab::Utils::Override

          override :execute
          def execute
            super

            copy_resource_weight_events
            copy_resource_iteration_events
          end

          private

          override :blocked_resource_event_attributes
          def blocked_resource_event_attributes
            super.push('epic_id')
          end

          def copy_resource_weight_events
            return unless both_respond_to?(:resource_weight_events)

            copy_events(ResourceWeightEvent.table_name, original_entity.resource_weight_events) do |event|
              event.attributes
                   .except('id')
                   .merge('issue_id' => new_entity.id, 'namespace_id' => new_entity.namespace_id)
            end
          end

          def copy_resource_iteration_events
            return unless both_respond_to?(:resource_iteration_events)

            copy_events(ResourceIterationEvent.table_name, original_entity.resource_iteration_events) do |event|
              event.attributes.except('id').merge(
                'issue_id' => new_entity.id,
                'action' => ResourceIterationEvent.actions[event.action]
              ).tap do |attrs|
                attrs['namespace_id'] = event.iteration.group_id unless attrs['namespace_id'].to_i > 0
              end
            end
          end
        end
      end
    end
  end
end
