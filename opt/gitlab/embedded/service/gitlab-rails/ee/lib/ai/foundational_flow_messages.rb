# frozen_string_literal: true

module Ai
  module FoundationalFlowMessages
    module_function

    def usage_billing_forbidden_error
      s_(
        "DuoFoundationalFlows|Usage billing is not available for this account. " \
          "To continue using this feature, contact your administrator."
      )
    end

    def concurrent_scan_limit_error(flow_name:)
      format(
        s_(
          "DuoFoundationalFlows|:warning: %{flow_name} did not run because this group already has the maximum " \
            "number of scans running. Retry the job when one of them finishes."
        ),
        flow_name: flow_name
      )
    end

    def usage_quota_exceeded_error(flow_name:)
      format(
        s_(
          "DuoFoundationalFlows|:warning: %{flow_name} did not run because no GitLab Credits remain for this " \
            "billing period. To continue using this flow, contact your administrator."
        ),
        flow_name: flow_name
      )
    end

    def namespace_missing_error(user)
      docs_url = Rails.application.routes.url_helpers.help_page_url(
        'user/profile/preferences.md',
        anchor: 'set-a-default-gitlab-duo-namespace'
      )

      format(
        s_(
          "DuoFoundationalFlows|:warning: %{user_reference}, you need to set a default GitLab Duo namespace " \
            "to use this flow. Please set a default GitLab Duo namespace in your %{link_start}preferences%{link_end}."
        ),
        user_reference: user.to_reference,
        link_start: "[",
        link_end: "](#{docs_url})"
      )
    end

    def no_eligible_runner_error(tag: ::Ai::DuoWorkflows::Workflow::WORKLOAD_TAG)
      format(
        s_(
          "DuoFoundationalFlows|This flow could not start because the project has no runner available to " \
            "run it. It needs an instance runner or a top-level group runner with the '%{tag}' tag and a " \
            "Docker-compatible executor."
        ),
        tag: tag
      )
    end

    def namespace_ci_minutes_used_up_error
      s_(
        "DuoFoundationalFlows|This flow could not start because the namespace has run out of compute minutes. " \
          "Ask someone with billing access to add compute minutes before trying again."
      )
    end

    def could_not_prepare_session_error
      s_(
        "DuoFoundationalFlows|This flow could not start because GitLab could not prepare the session. " \
          "Try again later. If the problem continues, contact your administrator."
      )
    end

    def failure_cause_no_activity
      minutes = ::Ai::DuoWorkflows::CleanStuckWorkflowsService::EXPIRATION_IN_MINUTES

      format(
        ns_(
          "DuoFoundationalFlows|The session timed out after %{count} minute with no activity",
          "DuoFoundationalFlows|The session timed out after %{count} minutes with no activity",
          minutes
        ),
        count: minutes
      )
    end

    def failure_cause_job_failed
      s_("DuoFoundationalFlows|The CI job for the session failed")
    end

    def failure_cause_preconditions_not_met
      s_("DuoFoundationalFlows|No runner or compute minutes were available for the session")
    end

    def failure_cause_compute_minutes_used_up
      s_("DuoFoundationalFlows|The namespace ran out of compute minutes")
    end

    def failure_cause_could_not_prepare_session
      s_("DuoFoundationalFlows|GitLab couldn't prepare the session")
    end

    def failure_cause_no_status_reported
      s_("DuoFoundationalFlows|The session ended without reporting a result")
    end

    def failure_cause_start_failed
      s_("DuoFoundationalFlows|The session couldn't start")
    end

    def failure_cause_workload_not_created
      s_("DuoFoundationalFlows|The CI job for the session couldn't be created")
    end

    def failure_cause_token_rejected
      s_("DuoFoundationalFlows|The session wasn't allowed to connect")
    end

    def repository_empty_error
      s_('DuoFoundationalFlows|Repository is empty')
    end
  end
end
