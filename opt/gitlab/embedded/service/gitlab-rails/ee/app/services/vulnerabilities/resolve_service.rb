# frozen_string_literal: true

require_dependency 'vulnerabilities/base_state_transition_service'

module Vulnerabilities
  class ResolveService < BaseStateTransitionService
    include Gitlab::InternalEventsTracking

    RESOLVE_PARAMS = {
      confirmed_by: nil,
      confirmed_at: nil,
      dismissed_by: nil,
      dismissed_at: nil
    }.freeze

    def initialize(user, vulnerability, comment, auto_resolved: false)
      super(user, vulnerability, comment)
      @auto_resolved = auto_resolved
    end

    private

    def update_vulnerability!
      update_vulnerability_with(state: :resolved, resolved_by: @user, resolved_at: Time.current,
        auto_resolved: @auto_resolved, **RESOLVE_PARAMS) do
        DestroyDismissalFeedbackService.new(@user, @vulnerability).execute # we can remove this as part of https://gitlab.com/gitlab-org/gitlab/-/issues/324899
        track_internal_event(
          'resolve_vulnerability',
          category: self.class.name,
          user: @user,
          namespace: @vulnerability.project.namespace,
          project: @vulnerability.project
        )

        Vulnerabilities::Reads::UpsertService.new(@vulnerability,
          { state: :resolved, auto_resolved: @auto_resolved }, projects: @project,
          findings: Array(@vulnerability.finding)).execute
      end
    end

    def to_state
      :resolved
    end

    def can_transition?
      !@vulnerability.resolved?
    end

    def required_permission
      :resolve_vulnerability
    end
  end
end
