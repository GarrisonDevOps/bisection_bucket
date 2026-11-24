# frozen_string_literal: true

module Vulnerabilities
  class FindOrCreateFromSecurityFindingService < ::BaseProjectService
    def initialize(
      project:, current_user:, params:, state:, present_on_default_branch:, skip_permission_check: false,
      defer_existing_state_update: false)
      super(project: project, current_user: current_user, params: params)
      @state = state
      @present_on_default_branch = present_on_default_branch
      @skip_permission_check = skip_permission_check
      @defer_existing_state_update = defer_existing_state_update
    end

    def execute
      if !@skip_permission_check && !can?(@current_user, :read_security_resource, @project)
        raise Gitlab::Access::AccessDeniedError
      end

      with_findings do |vulnerability_finding, security_finding, merge_target_findings|
        vulnerability, created = find_or_create_vulnerability(vulnerability_finding, security_finding)
        link_merge_target_findings(merge_target_findings, vulnerability)

        ServiceResponse.success(payload: { vulnerability:, created: })
      end
    end

    # Callers that defer the existing state update call this once their own writes succeed,
    # so a failed request leaves a pre-existing vulnerability unchanged.
    def update_existing_state(vulnerability)
      if vulnerability.state != @state.to_s
        update_state_for(vulnerability)
      elsif vulnerability.dismissed? # We only update when vulnerability is in dismissed state
        update_existing_state_transition(vulnerability)
      end
    end

    private

    def find_or_create_vulnerability(vulnerability_finding, security_finding)
      if vulnerability_finding.vulnerability_id.nil?
        vulnerability = Vulnerabilities::CreateService.new(
          @project,
          @current_user,
          finding_id: vulnerability_finding.id,
          state: @state,
          present_on_default_branch: @present_on_default_branch,
          comment: params[:comment],
          solution: security_finding.solution,
          dismissal_reason: params[:dismissal_reason],
          skip_permission_check: @skip_permission_check
        ).execute

        [vulnerability, vulnerability.persisted?]
      else
        vulnerability = Vulnerability.find(vulnerability_finding.vulnerability_id)
        update_existing_state(vulnerability) unless @defer_existing_state_update

        [vulnerability, false]
      end
    end

    # The target branch mirrors are written before the vulnerability exists, so link them
    # once it does. Ingestion reads `vulnerability_id` straight off the finding it matches
    # by UUID, and without it the merge would still open a duplicate.
    def link_merge_target_findings(findings, vulnerability)
      return unless vulnerability&.persisted?

      Array(findings).each do |finding|
        next if finding.vulnerability_id == vulnerability.id

        finding.update!(vulnerability_id: vulnerability.id)
      end
    end

    def update_state_for(vulnerability)
      Vulnerability.feature_flagged_transaction_for(project) do
        state_transition_params = {
          vulnerability: vulnerability,
          vulnerability_occurrence_id: vulnerability.finding&.id,
          from_state: vulnerability.state,
          to_state: @state,
          author: @current_user
        }

        state_transition_params[:comment] = params[:comment] if params[:comment]

        dismissal_reason = params[:dismissal_reason] if params[:dismissal_reason]
        state_transition_params[:dismissal_reason] = dismissal_reason

        Vulnerabilities::StateTransition.create!(state_transition_params)

        update_params = { state: @state }
        update_params.merge!(dismissed_by: @current_user, dismissed_at: Time.current) if @state.to_sym == :dismissed

        vulnerability.update!(update_params)

        if params[:dismissal_reason]
          update_vulnerability_read_dismissal_reason(vulnerability,
            { dismissal_reason: dismissal_reason, state: @state })
        end

        create_system_note(vulnerability, @current_user)
      end
    end

    def create_system_note(vulnerability, user)
      vulnerability.run_after_commit_or_now do
        SystemNoteService.change_vulnerability_state(vulnerability, user)
      end
    end

    def update_existing_state_transition(vulnerability)
      state_transition = vulnerability.state_transitions.by_to_states(:dismissed).last
      return unless state_transition
      return unless params[:comment] || params[:dismissal_reason]

      Vulnerability.feature_flagged_transaction_for(project) do
        state_transition.update!(params.slice(:comment, :dismissal_reason).compact)

        if params[:dismissal_reason]
          update_vulnerability_read_dismissal_reason(vulnerability,
            { dismissal_reason: params[:dismissal_reason] })
        end
      end
    end

    def update_vulnerability_read_dismissal_reason(vulnerability, params)
      if Feature.enabled?(:turn_off_vulnerability_read_create_db_trigger_function, @project)
        if @present_on_default_branch
          Vulnerabilities::Reads::UpsertService.new(vulnerability,
            params, projects: @project,
            findings: Array(vulnerability.finding)).execute
        end
      else
        # When the trigger is active, it handles state updates but not dismissal_reason
        vulnerability.vulnerability_read&.update!(params.slice(:dismissal_reason))
      end
    end

    def with_findings
      response = ::Vulnerabilities::Findings::FindOrCreateFromSecurityFindingService.new(
        project: project,
        current_user: current_user,
        params: params
      ).execute

      return response if response && response.error?

      yield(*response.payload.values_at(:vulnerability_finding, :security_finding, :merge_target_findings))
    end
  end
end
