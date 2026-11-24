# frozen_string_literal: true

module Gitlab
  module EventStore
    module Subscriptions
      class DependencyManagementSubscriptions < BaseSubscriptions
        def register
          store.subscribe ::DependencyManagement::SecurityUpdate::CreateMergeRequestWorker,
            to: ::Ci::PipelineFinishedEvent,
            if: ->(event) { dependency_management_pipeline?(event) }

          store.subscribe ::DependencyManagement::SecurityUpdate::TriggerResolveDependencyBumpWorkflowWorker,
            to: ::Ci::PipelineFinishedEvent,
            if: ->(event) { dependency_bump_mr_failure?(event) }

          store.subscribe ::DependencyManagement::SecurityUpdate::TrackResolveDependencyBumpPipelineWorker,
            to: ::Ci::PipelineFinishedEvent,
            if: ->(event) { dependency_bump_mr_pipeline?(event) }

          store.subscribe ::DependencyManagement::SecurityUpdate::TrackMergedMrWorker,
            to: ::MergeRequests::MergedEvent,
            if: ->(event) { dependency_management_mr?(event) }

          store.subscribe ::DependencyManagement::SecurityUpdate::TrackClosedMrWorker,
            to: ::MergeRequests::ClosedEvent,
            if: ->(event) { dependency_management_closed_mr?(event) }

          # ReopenedEvent carries no source, so the merge request itself decides.
          store.subscribe ::DependencyManagement::SecurityUpdate::TrackReopenedMrWorker,
            to: ::MergeRequests::ReopenedEvent,
            if: ->(event) { dependency_management_mr?(event) }
        end

        private

        def dependency_management_pipeline?(event)
          event.data[:source] == 'dependency_management_security_update'
        end

        def dependency_bump_mr_failure?(event)
          return false unless event.data[:status] == 'failed'

          dependency_bump_mr_pipeline?(event)
        end

        def dependency_bump_mr_pipeline?(event)
          # The update workload is not a merge request pipeline: keep it out of the
          # breaking-change trigger and the pipeline pass rate.
          return false if dependency_management_pipeline?(event)

          dependency_bump_branch?(event)
        end

        def dependency_bump_branch?(event)
          event.data[:source_ref]&.start_with?(
            "#{::DependencyManagement::SecurityUpdate::Request::BRANCH_PREFIX}/"
          )
        end

        def dependency_management_mr?(event)
          merge_request = MergeRequest.find_by_id(event.data[:merge_request_id])
          return false unless merge_request

          merge_request.dependency_management_mr?
        end

        def dependency_management_closed_mr?(event)
          event.data[:source] ==
            ::MergeRequests::ClosedEvent::SOURCE_TYPES[:dependency_management_auto_remediation]
        end
      end
    end
  end
end
