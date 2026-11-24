# frozen_string_literal: true

module EE
  module MergeRequests
    module CloseService
      extend ::Gitlab::Utils::Override

      override :execute
      def execute(merge_request, commit = nil, skip_reset: false)
        super.tap do
          if current_user.project_bot?
            log_audit_event(merge_request, 'merge_request_closed_by_project_bot',
              "Closed merge request #{merge_request.title}")
          end

          publish_event(merge_request)
          track_event(merge_request)
        end
      end

      def expire_unapproved_key(merge_request)
        merge_request.approval_state.expire_unapproved_key!
      end

      private

      def publish_event(merge_request)
        event_data = { merge_request_id: merge_request.id }
        source = closed_event_source(merge_request)
        event_data[:source] = source if source

        ::Gitlab::EventStore.publish(
          ::MergeRequests::ClosedEvent.new(data: event_data)
        )
      end

      def closed_event_source(merge_request)
        return unless merge_request.dependency_management_auto_remediation?

        ::MergeRequests::ClosedEvent::SOURCE_TYPES[:dependency_management_auto_remediation]
      end

      def track_event(merge_request)
        return unless merge_request.created_by_agentic_vr?

        track_internal_event(
          'close_vulnerability_resolution_merge_request',
          project: merge_request.project,
          additional_properties: {
            value: merge_request.id
          }
        )
      end
    end
  end
end
