# frozen_string_literal: true

# SystemNoteService
#
# Used for creating system notes (e.g., when a user references a merge request
# from an issue, an issue's assignee changes, an issue is closed, etc.
module EE
  module SystemNoteService
    extend ActiveSupport::Concern
    include ActionView::RecordIdentifier

    prepended do
      # ::SystemNoteService wants the methods to be available as both class and
      # instance methods. This removes the need for having to both `include` and
      # `extend` this module everywhere it is used.
      extend_mod_with('SystemNoteService') # rubocop: disable Cop/InjectEnterpriseEditionModule
    end

    def issue_promoted(noteable, noteable_ref, author, direction:)
      epics_service(noteable, author).issue_promoted(noteable_ref, direction: direction)
    end

    # Called when the health_stauts of an Issue is changed
    #
    # noteable   - Noteable object
    # project    - Project owning noteable
    # author     - User performing the change
    #
    # Example Note text:
    #
    #   "removed the health status"
    #   "changed health status to 'at risk'"
    #
    # Returns the created Note object
    def change_health_status_note(noteable, project, author, previous_status)
      issuables_service(noteable, project, author).change_health_status_note(previous_status)
    end

    # Called when the start or end date of an Issuable is changed
    #
    # noteable   - Noteable object
    # author     - User performing the change
    # date_type  - 'start date' or 'finish date'
    # date       - New date
    #
    # Example Note text:
    #
    #   "changed start date to FIXME"
    #
    # Returns the created Note object
    def change_epic_date_note(noteable, author, date_type, date)
      epics_service(noteable, author).change_epic_date_note(date_type, date)
    end

    # Called when 'merge train' is executed
    def merge_train(noteable, project, author, merge_train)
      merge_trains_service(noteable, project, author).enqueue(merge_train)
    end

    # Called when 'merge train' is canceled
    def cancel_merge_train(noteable, project, author)
      merge_trains_service(noteable, project, author).cancel
    end

    # Called when 'merge train' is aborted
    def abort_merge_train(noteable, project, author, reason)
      merge_trains_service(noteable, project, author).abort(reason)
    end

    # Called when 'add to merge train when checks pass' is executed
    def add_to_merge_train_when_checks_pass(noteable, project, author, sha)
      merge_trains_service(noteable, project, author).add_when_checks_pass(sha)
    end

    # Called when 'add to merge train when checks pass' is canceled
    def cancel_add_to_merge_train_when_checks_pass(noteable, project, author)
      merge_trains_service(noteable, project, author).cancel_add_when_checks_pass
    end

    # Called when 'add to merge train when checks pass' is aborted
    def abort_add_to_merge_train_when_checks_pass(noteable, project, author, reason)
      merge_trains_service(noteable, project, author).abort_add_when_checks_pass(reason)
    end

    # Called when state is changed for 'vulnerability'
    def change_vulnerability_state(noteable, author, body = nil)
      vulnerabilities_service(noteable, noteable.project, author).change_vulnerability_state(body)
    end

    # Called when quick action to publish an issue to status page is called
    def publish_issue_to_status_page(noteable, project, author)
      issuables_service(noteable, project, author).publish_issue_to_status_page
    end

    def notify_via_escalation(noteable, project, recipients, escalation_policy, type)
      escalations_service(noteable, project).notify_via_escalation(recipients, escalation_policy: escalation_policy, type: type)
    end

    def start_escalation(noteable, escalation_policy, author)
      escalations_service(noteable, noteable.project).start_escalation(escalation_policy, author)
    end

    def issuable_resource_link_added(incident, project, author, link_type)
      issuable_resource_links_service(incident, project, author).issuable_resource_link_added(link_type)
    end

    def issuable_resource_link_removed(incident, project, author, link_type)
      issuable_resource_links_service(incident, project, author).issuable_resource_link_removed(link_type)
    end

    # Called when Issuable got linked using `blocks` link
    #
    # noteable      - Noteable object
    # noteable_ref  - Noteable object
    # author        - User performing the linking action
    #
    # Returns the created Note object
    def block_issuable(noteable, noteable_ref, user)
      issuables_service(noteable, noteable.project, user).block_issuable(noteable_ref)
    end

    # Called when Issuable got blocked
    #
    # noteable      - Noteable object
    # noteable_ref  - Noteable object
    # author        - User performing the linking action
    #
    # Returns the created Note object
    def blocked_by_issuable(noteable, noteable_ref, user)
      issuables_service(noteable, noteable.project, user).blocked_by_issuable(noteable_ref)
    end

    def change_progress_note(noteable, user)
      issuables_service(noteable, noteable.project, user).change_progress_note
    end

    def change_color_note(noteable, user, previous_color)
      issuables_service(noteable, noteable.project, user).change_color_note(previous_color)
    end

    def change_checkin_reminder_note(noteable, user)
      issuables_service(noteable, noteable.project, user).change_checkin_reminder_note
    end

    def change_workplan_note(noteable, user, change)
      issuables_service(noteable, noteable.project, user).change_workplan_note(change)
    end

    def approvals_reset(noteable, user, cause, approvers)
      merge_requests_service(noteable, noteable.project, user).approvals_reset(cause, approvers)
    end

    def override_requested_changes(noteable, user, event)
      merge_requests_service(noteable, noteable.project, user).override_requested_changes(event)
    end

    def amazon_q_called(noteable, user, event)
      issuables_service(noteable, noteable.project, user).amazon_q_called(event)
    end

    def agent_session_started(noteable, project, session_id, trigger_source, service_account_user)
      agents_service(noteable, project).agent_session_started(session_id, trigger_source, service_account_user)
    end

    def agent_session_completed(noteable, project, session_id, service_account_user)
      agents_service(noteable, project).agent_session_completed(session_id, service_account_user)
    end

    def agent_session_failed(noteable, project, workflow, service_account_user)
      agents_service(noteable, project).agent_session_failed(workflow, service_account_user)
    end

    def agent_session_stopped(noteable, project, workflow, service_account_user)
      agents_service(noteable, project).agent_session_stopped(workflow, service_account_user)
    end

    def decision_recorded(decision, author)
      decisions_service(decision.work_item, author).decision_recorded(decision)
    end

    private

    def issuables_service(noteable, project, author)
      ::SystemNotes::IssuablesService.new(noteable: noteable, container: project, author: author)
    end

    def epics_service(noteable, author)
      ::SystemNotes::EpicsService.new(noteable: noteable, author: author)
    end

    def merge_requests_service(noteable, project, author)
      ::SystemNotes::MergeRequestsService.new(noteable: noteable, container: project, author: author)
    end

    def merge_trains_service(noteable, project, author)
      ::SystemNotes::MergeTrainService.new(noteable: noteable, container: project, author: author)
    end

    def vulnerabilities_service(noteable, project, author)
      ::SystemNotes::VulnerabilitiesService.new(noteable: noteable, container: project, author: author)
    end

    def escalations_service(noteable, project)
      ::SystemNotes::EscalationsService.new(noteable: noteable, container: project)
    end

    def issuable_resource_links_service(noteable, project, author)
      ::SystemNotes::IssuableResourceLinksService.new(noteable: noteable, container: project, author: author)
    end

    def agents_service(noteable, project)
      ::SystemNotes::AgentsService.new(noteable: noteable, container: project)
    end

    def decisions_service(work_item, author)
      ::SystemNotes::DecisionsService.new(noteable: work_item, container: work_item.resource_parent, author: author)
    end
  end
end
