# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class ValidatePolicyService < ::BaseContainerService
      include ::Gitlab::Utils::StrongMemoize
      include Security::SecurityOrchestrationPolicies::CadenceChecker

      ValidationError = Struct.new(:field, :level, :message, :title, :index)

      DEFAULT_VALIDATION_ERROR_FIELD = :base
      SECURITY_REPORT_TIME_WINDOW_MIN_MINUTES = 1
      SECURITY_REPORT_TIME_WINDOW_MAX_MINUTES = 10080
      PIPELINE_EXECUTION_SCHEDULE_TIME_WINDOW_MAX_SECONDS = 2_629_746

      # rubocop:disable Metrics/CyclomaticComplexity -- flat branching
      # rubocop:disable Metrics/PerceivedComplexity -- policy validation
      # rubocop:disable Metrics/AbcSize -- policy validation
      def execute
        return error_with_title(s_('SecurityOrchestration|Empty policy name')) if blank_name?

        if exceeds_pipeline_execution_schedule_policies_limit?
          message = format(
            s_('SecurityOrchestration|Security policy project exceeds the maximum of ' \
              '%{limit} scheduled pipeline execution policies'),
            limit: pipeline_execution_schedule_policies_limit
          )
          return error_with_title(message)
        end

        if dependency_firewall_policy_unavailable?
          return error_with_title(s_('SecurityOrchestration|Invalid policy type'))
        end

        return success if policy_disabled?

        return error_with_title(s_('SecurityOrchestration|Invalid policy type')) if invalid_policy_type?

        if exceeds_action_limit?
          return error_with_title(format(s_('SecurityOrchestration|Policy exceeds the maximum of %{limit} actions'), limit: scan_execution_policies_action_limit))
        end

        if exceeds_scan_execution_policy_schedule_limit?
          return error_with_title(format(s_('SecurityOrchestration|Policy exceeds the maximum of %{limit} rule schedules'), limit: scan_execution_policies_schedule_limit))
        end

        if exceeds_pipeline_execution_schedule_policy_schedule_limit?
          return error_with_title(format(s_('SecurityOrchestration|Policy exceeds the maximum of %{limit} pipeline execution schedules'), limit: pipeline_execution_schedule_policies_schedule_limit))
        end

        if exceeds_pipeline_execution_schedule_policy_branches_limit?
          return error_with_title(format(s_('SecurityOrchestration|Policy exceeds the maximum of %{limit} branches per schedule'), limit: pipeline_execution_schedule_policy_branches_limit), field: :branches)
        end

        return pipeline_execution_schedule_time_window_error if invalid_pipeline_execution_schedule_time_window?

        if exceeds_approver_action_limit?
          return error_with_title(format(s_('SecurityOrchestration|Policy exceeds the maximum of %{limit} approver actions'), limit: approval_action_limit))
        end

        if blank_branch_for_rule?
          return error_with_title(s_('SecurityOrchestration|Policy cannot be enabled without branch information'), field: :branches)
        end

        if missing_branch_for_rule?
          return error_with_title(format(s_('SecurityOrchestration|Policy cannot be enabled for non-existing branches (%{branches})'), branches: missing_branch_names.join(', ')), field: :branches)
        end

        if default_branch_unprotected?
          return error_with_title(s_('SecurityOrchestration|This merge request approval policy targets the default branch, but the default branch is not protected in this project. To set up this policy, the default branch must be protected.'), field: :branches)
        end

        if invalid_branch_types?
          return error_with_title(s_('SecurityOrchestration|Branch types don\'t match any existing branches.'), field: :branches)
        end

        return error_with_title(s_('SecurityOrchestration|Timezone is invalid'), field: :timezone) if invalid_timezone?

        if invalid_vulnerability_age?
          return error_with_title(s_('SecurityOrchestration|Vulnerability age requires previously existing vulnerability states (detected, confirmed, resolved, or dismissed)'), field: :vulnerability_age)
        end

        if invalid_compliance_framework_ids?
          return error_with_title(s_('SecurityOrchestration|Invalid Compliance Framework ID(s)'), field: :compliance_frameworks)
        end

        if invalid_security_report_time_window?
          return error_with_title(s_('SecurityOrchestration|Invalid security report time window'), field: :security_report_time_window)
        end

        if required_approvals_exceed_eligible_approvers?
          return errors_with_title(s_('SecurityOrchestration|Required approvals exceed eligible approvers.'), title: s_('SecurityOrchestration|Logic error'), field: :actions, indices: multiple_approvals_failed_action_indices)
        end

        return error_with_title(s_('SecurityOrchestration|Cadence is invalid'), field: :cadence) if invalid_cadence?

        if agentic_scan_unavailable?
          return error_with_title(s_('SecurityOrchestration|Business logic scans are not available for this project or group'), field: :actions)
        end

        if agentic_scan_with_non_schedule_rule?
          return error_with_title(s_('SecurityOrchestration|Business logic scans can only be used with schedule rules'), field: :rules)
        end

        success
      end
      # rubocop:enable Metrics/CyclomaticComplexity
      # rubocop:enable Metrics/PerceivedComplexity
      # rubocop:enable Metrics/AbcSize

      private

      def errors_with_title(message, field: DEFAULT_VALIDATION_ERROR_FIELD, title: nil, level: :error, indices: [])
        validation_errors = indices.map { |index| ValidationError.new(field, level, message, title, index).to_h }

        construct_errors([message], validation_errors)
      end

      def error_with_title(message, field: DEFAULT_VALIDATION_ERROR_FIELD, title: nil, level: :error)
        construct_errors([message], [ValidationError.new(field, level, message, title, 0).to_h])
      end

      def construct_errors(messages, validation_errors)
        pass_back = {
          details: messages,
          validation_errors: validation_errors
        }

        error(s_('SecurityOrchestration|Invalid policy'), :bad_request, pass_back: pass_back)
      end

      def policy_disabled?
        !policy&.[](:enabled)
      end

      def default_branch_unprotected?
        return false unless project_container?
        return false unless approval_policy?
        return false unless policy[:rules]&.any? { |rule| rule[:branch_type] == "default" }

        !ProtectedBranch.protected?(project, project.default_branch)
      end

      def invalid_policy_type?
        return true if policy[:type].blank?

        Security::OrchestrationPolicyConfiguration::AVAILABLE_POLICY_TYPES.exclude?(policy_type)
      end

      def dependency_firewall_policy_unavailable?
        policy_type == :dependency_firewall_policy &&
          !::Security::DependencyFirewall::Availability.access_enabled?(container)
      end

      def exceeds_approver_action_limit?
        return false unless approval_policy?

        approver_actions_count = policy[:actions]&.count do |action|
          action[:type] == Security::ScanResultPolicy::REQUIRE_APPROVAL
        end || 0

        approver_actions_count > approval_action_limit
      end

      def exceeds_action_limit?
        return false if removing_policy?
        return false if !scan_execution_policy? || scan_execution_policies_action_limit == 0

        (policy[:actions]&.count || 0) > scan_execution_policies_action_limit
      end

      def exceeds_scan_execution_policy_schedule_limit?
        return false if removing_policy?
        return false if !scan_execution_policy? || scan_execution_policies_schedule_limit == 0

        schedule_rules = policy[:rules]&.select { |rule| rule[:type] == ::Security::ScanExecutionPolicy::RULE_TYPES[:schedule] }

        (schedule_rules&.size || 0) > scan_execution_policies_schedule_limit
      end

      def exceeds_pipeline_execution_schedule_policy_schedule_limit?
        return false if removing_policy? || !pipeline_execution_schedule_policy?

        (policy[:schedules]&.size || 0) > pipeline_execution_schedule_policies_schedule_limit
      end

      def exceeds_pipeline_execution_schedule_policies_limit?
        return false unless pipeline_execution_schedule_policy?
        return false unless params[:operation] == :append

        existing_pipeline_execution_schedule_policies_count >= pipeline_execution_schedule_policies_limit
      end

      def exceeds_pipeline_execution_schedule_policy_branches_limit?
        return false if removing_policy? || !pipeline_execution_schedule_policy?

        policy[:schedules]&.any? do |schedule|
          (schedule[:branches]&.size || 0) > pipeline_execution_schedule_policy_branches_limit
        end
      end

      def invalid_pipeline_execution_schedule_time_window?
        return false if removing_policy? || !pipeline_execution_schedule_policy?

        !schedule_time_window_error_index.nil?
      end

      def pipeline_execution_schedule_time_window_error
        index = schedule_time_window_error_index
        max_days = (PIPELINE_EXECUTION_SCHEDULE_TIME_WINDOW_MAX_SECONDS / 1.day).round
        friendly_msg = format(
          s_('SecurityOrchestration|Schedule time window value exceeds the maximum allowed duration of approximately %{max_days} days'),
          max_days: max_days
        )
        # The path format is required by parseError on the frontend to route this error to the
        # DurationSelector component via isCauseOfError. The policy index is hardcoded as 0
        # because parseError discards it when matching error paths.
        path_msg = "property '/pipeline_execution_schedule_policy/0/schedules/#{index}/time_window/value' is invalid"

        validation_error = ValidationError.new(:time_window, :error, friendly_msg, nil, index)
        construct_errors([friendly_msg, path_msg], [validation_error.to_h])
      end

      def schedule_time_window_error_index
        policy[:schedules]&.find_index do |schedule|
          next false unless schedule.is_a?(Hash)

          value = schedule.dig(:time_window, :value)
          value.is_a?(Numeric) && value > PIPELINE_EXECUTION_SCHEDULE_TIME_WINDOW_MAX_SECONDS
        end
      end
      strong_memoize_attr :schedule_time_window_error_index

      def blank_name?
        policy[:name].blank?
      end

      def blank_branch_for_rule?
        return false unless scan_execution_policy?

        policy[:rules].any? do |rule|
          rule.values_at(:agents, :branches, :branch_type).all?(&:blank?)
        end
      end

      def missing_branch_for_rule?
        return false if container.blank?
        return false unless project_container?
        return false if pipeline_execution_policy?

        missing_branch_names.present?
      end

      def invalid_compliance_framework_ids?
        return false if project_container?
        return false if compliance_framework_ids.blank?

        valid_count = (container.compliance_framework_ids_with_csp & compliance_framework_ids).count

        valid_count != compliance_framework_ids.count
      end

      def required_approvals_exceed_eligible_approvers?
        multiple_approvals_failed_action_indices&.any?
      end

      def approvals_required?(action)
        return false unless action

        # For group-level policies the number of role_approvers is project-dependent
        return false if group_container? && action.key?(:role_approvers)

        action.key?(:approvals_required)
      end

      def multiple_approvals_failed_action_indices
        return [] if removing_policy?
        return [] unless approval_policy?
        return [] if approval_requiring_actions.blank?

        result = ::Security::SecurityOrchestrationPolicies::FetchPolicyApproversService.new(
          policy: policy,
          container: container,
          current_user: current_user
        ).execute

        return [] unless result[:status] == :success

        approval_requiring_actions.each_with_object([]).with_index do |(action, indices), index|
          approvers = result[:approvers]&.at(index)
          indices << index if approvers && approvals_required?(action) && invalid_approvals_required?(action, approvers)
        end
      end
      strong_memoize_attr :multiple_approvals_failed_action_indices

      def invalid_approvals_required?(action, approvers)
        approvals_required = action[:approvals_required] || 0

        eligible_user_ids = Set.new
        users, groups, roles, custom_roles = approvers.values_at(:users, :all_groups, :roles, :custom_roles)

        eligible_user_ids.merge(users.pluck(:id)) # rubocop:disable CodeReuse/ActiveRecord
        return false if eligible_user_ids.size >= approvals_required

        eligible_user_ids.merge(user_ids_by_groups(groups))
        return false if eligible_user_ids.size >= approvals_required

        eligible_user_ids.merge(user_ids_by_roles(roles))
        return false if eligible_user_ids.size >= approvals_required

        eligible_user_ids.merge(user_ids_by_project_and_custom_roles(custom_roles))
        return false if eligible_user_ids.size >= approvals_required

        eligible_user_ids.merge(user_ids_by_groups_and_custom_roles(custom_roles))
        eligible_user_ids.size < approvals_required
      end

      def user_ids_by_groups(groups)
        return [] if groups.empty?

        GroupMember.eligible_approvers_ids_by_groups(groups.self_and_ancestors)
      end

      def user_ids_by_roles(roles)
        return [] if roles.empty? || group_container?

        roles_map = Gitlab::Access.sym_options_with_owner
        access_levels = roles.filter_map { |role| roles_map[role.to_sym] }

        ProjectAuthorization.eligible_approvers_by_project_id_and_access_levels(project.id, access_levels).pluck_user_ids
      end

      def user_ids_by_project_and_custom_roles(custom_roles)
        return [] if custom_roles.empty? || group_container?

        ProjectMember.eligible_approvers_ids_by_project_id_and_custom_roles(project.id, custom_roles)
      end

      def user_ids_by_groups_and_custom_roles(custom_roles)
        return [] if custom_roles.empty?

        group = project_container? ? project.group : container

        return [] if group.blank?

        GroupMember.eligible_approvers_ids_by_group_ids_and_custom_roles(group.self_and_ancestor_ids, custom_roles)
      end

      def missing_branch_names
        strong_memoize(:missing_branch_names) do
          next [] if policy[:rules].blank?

          policy[:rules]
            .select { |rule| rule[:agents].blank? }
            .flat_map { |rule| rule[:branches] }
            .compact
            .uniq
            .select { |pattern| RefMatcher.new(pattern).matching(branches_for_project).blank? }
        end
      end

      def policy
        @policy ||= params[:policy]
      end

      def removing_policy?
        params[:operation] == :remove
      end

      def branches_for_project
        strong_memoize(:branches_for_project) do
          container.repository.branch_names
        end
      end

      def invalid_branch_types?
        return false if container.blank? || !project_container? || policy[:rules].blank?

        service = Security::SecurityOrchestrationPolicies::PolicyBranchesService.new(project: container)

        policy[:rules].select { |rule| rule[:branch_type].present? }
                      .any? do |rule|
          if approval_policy?
            service.scan_result_branches([rule]).empty?
          elsif scan_execution_policy? && !service.skip_validation?(rule)
            service.scan_execution_branches([rule]).empty?
          end
        end
      end

      def invalid_timezone?
        return false unless scan_execution_policy?

        policy[:rules].select { |rule| rule[:timezone] }
                      .any? do |rule|
          TZInfo::Timezone.get(rule[:timezone])
          false
        rescue TZInfo::InvalidTimezoneIdentifier
          true
        end
      end

      def invalid_vulnerability_age?
        return false unless approval_policy?

        policy[:rules].select { |rule| rule[:vulnerability_age].present? }
                      .any? do |rule|
          ((rule[:vulnerability_states] || []) & ::Enums::Vulnerability.vulnerability_states.keys.map(&:to_s)).empty?
        end
      end

      def invalid_security_report_time_window?
        return false unless approval_policy?

        security_report_time_window = policy.dig(:policy_tuning, :security_report_time_window)
        security_report_time_window.present? && (
          security_report_time_window < SECURITY_REPORT_TIME_WINDOW_MIN_MINUTES ||
            security_report_time_window > SECURITY_REPORT_TIME_WINDOW_MAX_MINUTES)
      end

      def policy_type
        policy[:type]&.to_sym
      end

      def approval_policy?
        policy_type == :approval_policy
      end

      def scan_execution_policy?
        policy_type == :scan_execution_policy
      end

      def pipeline_execution_policy?
        policy_type == :pipeline_execution_policy
      end

      def pipeline_execution_schedule_policy?
        policy_type == :pipeline_execution_schedule_policy
      end

      def compliance_framework_ids
        policy.dig(:policy_scope, :compliance_frameworks)&.pluck(:id)&.uniq
      end
      strong_memoize_attr :compliance_framework_ids

      def approval_requiring_actions
        Array.wrap(policy[:actions]).select { |action| action[:type] == Security::ScanResultPolicy::REQUIRE_APPROVAL }
      end
      strong_memoize_attr :approval_requiring_actions

      def scan_execution_policies_action_limit
        Gitlab::CurrentSettings.scan_execution_policies_action_limit
      end
      strong_memoize_attr :scan_execution_policies_action_limit

      def scan_execution_policies_schedule_limit
        Gitlab::CurrentSettings.scan_execution_policies_schedule_limit
      end
      strong_memoize_attr :scan_execution_policies_schedule_limit

      def pipeline_execution_schedule_policies_schedule_limit
        Security::PipelineExecutionSchedulePolicy::SCHEDULES_PER_POLICY_LIMIT
      end
      strong_memoize_attr :pipeline_execution_schedule_policies_schedule_limit

      def pipeline_execution_schedule_policies_limit
        Security::PipelineExecutionSchedulePolicy::POLICY_LIMIT
      end
      strong_memoize_attr :pipeline_execution_schedule_policies_limit

      def existing_pipeline_execution_schedule_policies_count
        container
          &.security_orchestration_policy_configuration
          &.pipeline_execution_schedule_policy
          &.size || 0
      end
      strong_memoize_attr :existing_pipeline_execution_schedule_policies_count

      def pipeline_execution_schedule_policy_branches_limit
        Security::PipelineExecutionSchedulePolicy::BRANCHES_PER_POLICY_LIMIT
      end
      strong_memoize_attr :pipeline_execution_schedule_policy_branches_limit

      def approval_action_limit
        Security::ScanResultPolicy::APPROVERS_ACTIONS_LIMIT
      end
      strong_memoize_attr :approval_action_limit

      def agentic_scan?
        return false if removing_policy? || !scan_execution_policy?

        Array.wrap(policy[:actions]).any? do |action|
          action.is_a?(Hash) && ::Security::ScanExecutionPolicy.agentic_scan_type?(action[:scan])
        end
      end
      strong_memoize_attr :agentic_scan?

      def agentic_scan_unavailable?
        agentic_scan? && !::Security::ScanExecutionPolicy.agentic_scan_available?(container)
      end

      def agentic_scan_with_non_schedule_rule?
        agentic_scan? &&
          Array.wrap(policy[:rules]).any? do |rule|
            rule[:type] != ::Security::ScanExecutionPolicy::RULE_TYPES[:schedule]
          end
      end

      def invalid_cadence?
        return false unless scan_execution_policy?

        policy[:rules].select { |rule| rule[:cadence] }
                      .any? do |rule|
          !(Gitlab::Ci::CronParser.new(rule[:cadence]).cron_valid? && valid_cadence?(rule[:cadence]))
        end
      end
    end
  end
end
