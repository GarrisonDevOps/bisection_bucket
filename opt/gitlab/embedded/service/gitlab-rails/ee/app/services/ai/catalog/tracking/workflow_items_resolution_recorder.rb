# frozen_string_literal: true

module Ai
  module Catalog
    module Tracking
      class WorkflowItemsResolutionRecorder
        include Gitlab::InternalEventsTracking

        def initialize(workflow:, current_user:, root_item:)
          @workflow = workflow
          @current_user = current_user
          @root_item = root_item
        end

        def execute
          sub_items = root_item[:sub_items]
          reason = root_item[:sub_items_skipped_reason]
          refused = sub_items.select { |sub_item| sub_item[:error] }

          track_resolution(sub_items.size - refused.size, refused.size, reason)
          refused.each { |sub_item| audit_refused(sub_item) }
        end

        private

        attr_reader :workflow, :current_user, :root_item

        def track_resolution(served_count, refused_count, reason)
          track_internal_event(
            'resolve_ai_catalog_flow_sub_items',
            user: current_user,
            project: project,
            additional_properties: {
              label: outcome(refused_count, reason),
              property: reason,
              value: served_count,
              refused_count: refused_count,
              **identity_properties
            }.compact
          )
        end

        def identity_properties
          WorkflowIdentityPropertiesBuilder.new(workflow).to_h
        end

        # DWS fails the whole session when any sub-agent is refused, so one
        # refusal makes the resolution a refusal even when others were served.
        def outcome(refused_count, reason)
          return 'skipped' if reason
          return 'refused' if refused_count > 0

          'served'
        end

        def audit_refused(sub_item)
          audit(
            'ai_catalog_flow_sub_agent_refused',
            "AI Catalog sub-agent #{refused_label(sub_item)} was refused for this session",
            { item_id: sub_item[:item_id], version: sub_item[:version], code: sub_item[:error][:code] }
          )
        end

        def refused_label(sub_item)
          [sub_item[:item_id], ("(version #{sub_item[:version]})" if sub_item[:version])].compact.join(' ')
        end

        def audit(name, message, details)
          ::Gitlab::Audit::Auditor.audit(
            name: name,
            author: current_user,
            scope: project,
            target: workflow,
            target_details: "#{workflow.workflow_definition} session #{workflow.id}",
            message: message,
            additional_details: details
          )
        end

        def project
          workflow.project
        end
      end
    end
  end
end
