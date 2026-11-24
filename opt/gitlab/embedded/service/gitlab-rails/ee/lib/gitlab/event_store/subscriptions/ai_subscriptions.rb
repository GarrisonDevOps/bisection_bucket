# frozen_string_literal: true

module Gitlab
  module EventStore
    module Subscriptions
      class AiSubscriptions < BaseSubscriptions
        def register
          register_active_context_events
          register_workloads_events
          register_workflows_events
          register_merge_requests_events
          register_work_items_events
        end

        private

        def register_active_context_events
          store.subscribe ::Ai::ActiveContext::Code::CreateEnabledNamespaceEventWorker,
            to: ::Ai::ActiveContext::Code::CreateEnabledNamespaceEvent

          store.subscribe ::Ai::ActiveContext::Code::MarkRepositoryAsReadyEventWorker,
            to: ::Ai::ActiveContext::Code::MarkRepositoryAsReadyEvent

          store.subscribe ::Ai::ActiveContext::Code::MarkRepositoryAsPendingDeletionEventWorker,
            to: ::Ai::ActiveContext::Code::MarkRepositoryAsPendingDeletionEvent

          store.subscribe ::Ai::ActiveContext::Code::ProcessPendingEnabledNamespaceEventWorker,
            to: ::Ai::ActiveContext::Code::ProcessPendingEnabledNamespaceEvent

          store.subscribe ::Ai::ActiveContext::Code::ProcessInvalidEnabledNamespaceEventWorker,
            to: ::Ai::ActiveContext::Code::ProcessInvalidEnabledNamespaceEvent
        end

        def register_workloads_events
          store.subscribe ::Ai::DuoWorkflows::UpdateWorkflowStatusEventWorker,
            to: ::Ci::Workloads::WorkloadFinishedEvent

          store.subscribe ::Ai::Messaging::CallbackWorker,
            to: ::Ci::Workloads::WorkloadFinishedEvent
        end

        def register_workflows_events
          store.subscribe ::Ai::FlowTriggers::ApplyOnFinishSettingsWorker,
            to: ::Ai::DuoWorkflows::WorkflowFinishedCloudEvent,
            if: ->(event) { ::Ai::FlowTriggers::ApplyOnFinishSettingsWorker.dispatch?(event) }

          store.subscribe ::Ai::FlowTriggers::FixLoop::FixRunEndedWorker,
            to: [
              ::Ai::DuoWorkflows::WorkflowFinishedCloudEvent,
              ::Ai::DuoWorkflows::WorkflowFailedEvent,
              ::Ai::DuoWorkflows::WorkflowStoppedEvent
            ],
            if: ->(event) { ::Ai::FlowTriggers::FixLoop::FixRunEndedWorker.dispatch?(event) }

          store.subscribe ::Ai::Messaging::CallbackWorker,
            to: ::Ai::DuoWorkflows::WorkflowStartedEvent

          store.subscribe ::Ai::Messaging::CallbackWorker,
            to: ::Ai::DuoWorkflows::WorkflowFinishedEvent

          store.subscribe ::Ai::Messaging::CallbackWorker,
            to: ::Ai::DuoWorkflows::WorkflowApprovalRequiredEvent

          store.subscribe ::Ai::Messaging::CallbackWorker,
            to: ::Ai::DuoWorkflows::WorkflowInputRequiredEvent

          # A messaging session publishes both shapes: the aggregated one for this
          # worker, and the split one for the session lifecycle worker. Only
          # `status_event` tells them apart, so matching on `adapter` too would
          # deliver the same ending twice.
          store.subscribe ::Ai::Messaging::CallbackWorker,
            to: ::Ai::DuoWorkflows::WorkflowFailedEvent,
            if: ->(event) { event.event_data[:status_event].present? }

          # Complements the guard above: `status_event` marks the aggregated copy,
          # which belongs to the messaging worker. Without this, a payload carrying
          # both keys would run the hook for the same ending twice.
          [
            ::Ai::DuoWorkflows::WorkflowFinishedCloudEvent,
            ::Ai::DuoWorkflows::WorkflowFailedEvent,
            ::Ai::DuoWorkflows::WorkflowStoppedEvent
          ].each do |event_class|
            store.subscribe ::Ai::DuoWorkflows::SessionLifecycleWorker,
              to: event_class,
              if: ->(event) {
                event.event_data[:status_event].blank? &&
                  ::Ai::Catalog::FoundationalFlow.session_hook?(event.event_data[:workflow_definition], event_class)
              }
          end
        end

        def register_merge_requests_events
          store.subscribe ::Ai::Catalog::Flows::ExecuteMergeRequestCreatedWorkflowTriggersWorker,
            to: ::MergeRequests::AfterCreateCloudEvent,
            if: ->(event) {
              ::Ai::FlowTrigger.registered_for?(event.event_data[:project_id], :merge_request)
            }

          store.subscribe ::Ai::Catalog::Flows::ExecuteMergeRequestReadyWorkflowTriggersWorker,
            to: ::MergeRequests::ReadyEvent,
            if: ->(event) {
              ::Ai::FlowTrigger.registered_for?(event.event_data[:project_id], :merge_request_ready)
            }

          store.subscribe ::Ai::Catalog::Flows::ExecuteCodeConflictAiWorkflowTriggersWorker,
            to: ::MergeRequests::CodeConflictEvent,
            if: ->(event) {
              ::Ai::FlowTrigger.registered_for?(event.event_data[:project_id], :merge_request_code_conflict)
            }

          store.subscribe ::Ai::Catalog::Flows::ExecuteMergeRequestApprovedWorkflowTriggersWorker,
            to: ::MergeRequests::ApprovedCloudEvent,
            if: ->(event) {
              ::Ai::FlowTrigger.registered_for?(event.event_data[:project_id], :merge_request)
            }

          store.subscribe ::Ai::FlowTriggers::FixLoop::ReviewerApprovedWorker,
            to: ::MergeRequests::ApprovedCloudEvent,
            if: ->(event) { ::Ai::FlowTriggers::FixLoop::ReviewerApprovedWorker.dispatch?(event) }

          store.subscribe ::Ai::Catalog::Flows::ExecuteMergeRequestMergedWorkflowTriggersWorker,
            to: ::MergeRequests::MergedCloudEvent,
            if: ->(event) {
              ::Ai::FlowTrigger.registered_for?(event.event_data[:project_id], :merge_request)
            }

          store.subscribe ::Ai::Catalog::Flows::ExecuteMergeRequestRequestedChangesWorkflowTriggersWorker,
            to: ::MergeRequests::RequestedChangesCloudEvent,
            if: ->(event) {
              ::Ai::FlowTrigger.registered_for?(event.event_data[:project_id], :merge_request)
            }
        end

        def register_work_items_events
          store.subscribe ::Ai::Catalog::Flows::ExecuteWorkItemCreatedWorkflowTriggersWorker,
            to: ::WorkItems::CreatedEvent,
            if: ->(event) {
              ::Ai::FlowTrigger.registered_for?(event.event_data[:project_id], :work_item)
            }

          store.subscribe ::Ai::Catalog::Flows::ExecuteWorkItemStatusChangedWorkflowTriggersWorker,
            to: ::WorkItems::StatusChangedEvent,
            if: ->(event) {
              ::Ai::FlowTrigger.registered_for?(event.event_data[:project_id], :work_item)
            }
        end
      end
    end
  end
end
