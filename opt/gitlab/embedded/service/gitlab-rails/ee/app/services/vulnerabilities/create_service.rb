# frozen_string_literal: true

module Vulnerabilities
  class CreateService
    include Gitlab::Allowable
    include Gitlab::Utils::StrongMemoize

    def initialize(
      project,
      author,
      finding_id:,
      **params
    )
      @project = project
      @author = author
      @finding_id = finding_id
      @state = params[:state]
      @present_on_default_branch = params.fetch(:present_on_default_branch, true)
      @comment = params[:comment]
      @dismissal_reason = params[:dismissal_reason]
      @skip_permission_check = params.fetch(:skip_permission_check, false)
      @solution = params[:solution]
    end

    def execute
      if !@skip_permission_check && !can?(@author, :read_security_resource, @project)
        raise Gitlab::Access::AccessDeniedError
      end

      vulnerability = Vulnerability.new

      Vulnerabilities::Finding.feature_flagged_transaction_for(@project) do
        save_vulnerability(vulnerability, finding)
      rescue ActiveRecord::RecordNotFound
        vulnerability.errors.add(:base, _('finding is not found or is already attached to a vulnerability'))
        raise ActiveRecord::Rollback
      end

      if vulnerability.persisted?
        attributes = {
          vulnerability_occurrence_id: finding.id,
          traversal_ids: @project.namespace.traversal_ids
        }
        attributes[:dismissal_reason] = @dismissal_reason if @dismissal_reason
        if Security::VAC.enabled?(@project) && finding.security_project_tracked_context_id
          attributes[:security_project_tracked_context_id] =
            finding.security_project_tracked_context_id
        end

        Vulnerabilities::StatisticsUpdateService.update_for(vulnerability)
        Vulnerabilities::Findings::RiskScoreCalculationService.calculate_for(vulnerability)

        if @present_on_default_branch
          Vulnerabilities::Reads::UpsertService.new(
            vulnerability, attributes, projects: @project, update_all_vulnerabilities: true,
            findings: [finding]
          ).execute
        end

        mark_project_as_vulnerable(vulnerability)
      end

      vulnerability
    end

    private

    def save_vulnerability(vulnerability, finding)
      from_state = finding.state

      vulnerability.assign_attributes(
        author: @author,
        project: @project,
        title: finding.name.truncate(::Issuable::TITLE_LENGTH_MAX),
        state: @state || finding.state,
        solution: @solution,
        severity: finding.severity,
        severity_overridden: false,
        report_type: finding.report_type,
        dismissed_at: state_timestamp_for(:dismissed),
        dismissed_by_id: state_author_id_for(:dismissed),
        confirmed_at: state_timestamp_for(:confirmed),
        confirmed_by_id: state_author_id_for(:confirmed),
        resolved_at: state_timestamp_for(:resolved),
        resolved_by_id: state_author_id_for(:resolved),
        present_on_default_branch: @present_on_default_branch,
        finding_id: finding.id
      )

      vulnerability.save && (vulnerability.findings << finding)
      create_state_transition_if_needed(vulnerability, from_state) if @state
    end

    def state_timestamp_for(state)
      @state&.to_sym == state ? Time.current : nil
    end

    def state_author_id_for(state)
      @state&.to_sym == state ? @author.id : nil
    end

    def create_state_transition_if_needed(vulnerability, from_state)
      return if from_state == @state

      state_transition_params = {
        vulnerability: vulnerability,
        vulnerability_occurrence_id: finding.id,
        from_state: from_state,
        to_state: @state,
        author: @author
      }

      state_transition_params[:comment] = @comment if @comment
      state_transition_params[:dismissal_reason] = @dismissal_reason if @dismissal_reason

      Vulnerabilities::StateTransition.create!(state_transition_params)
      create_system_note(vulnerability, @author)
    end

    def create_system_note(vulnerability, user)
      vulnerability.run_after_commit_or_now do
        SystemNoteService.change_vulnerability_state(vulnerability, user)
      end
    end

    # Some callers run this service inside a Sec database transaction, but project_settings is in the main
    # database, and GitLab does not allow one transaction to write to both. Waiting for the commit also
    # means a vulnerability that gets rolled back never sets the flag.
    def mark_project_as_vulnerable(vulnerability)
      vulnerability.run_after_commit_or_now do
        project.project_setting.mark_as_vulnerable!
      end
    end

    def finding
      # we're using `lock` instead of `with_lock` to avoid extra call to `find` under the hood
      @finding ||= Vulnerabilities::Finding.lock_for_confirmation!(project: @project, id: @finding_id)
    end
  end
end
