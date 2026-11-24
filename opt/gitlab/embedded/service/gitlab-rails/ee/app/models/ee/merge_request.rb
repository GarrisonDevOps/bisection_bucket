# frozen_string_literal: true

module EE
  module MergeRequest
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    include ::Gitlab::Allowable
    include ::Gitlab::Utils::StrongMemoize
    include FromUnion

    MAX_CHECKED_PIPELINES_FOR_SECURITY_REPORT_COMPARISON = 10
    MAX_CHECKED_ADDITIONAL_SHAS_FOR_SECURITY_REPORT_COMPARISON = 10
    DUO_VULNERABILITY_FIX_BRANCH_PREFIX = 'duo/fix/'

    prepended do
      include Auditable
      include Elastic::ApplicationVersionedSearch
      include DeprecatedApprovalsBeforeMerge
      include UsageStatistics
      include IterationEventable

      has_many :vulnerability_merge_request_links,
        class_name: 'Vulnerabilities::MergeRequestLink',
        inverse_of: :merge_request
      has_many :duo_workflow_links,
        class_name: '::Ai::DuoWorkflows::WorkflowMergeRequest',
        foreign_key: :merge_request_id,
        inverse_of: :merge_request
      has_many :linked_duo_workflows,
        through: :duo_workflow_links,
        source: :workflow,
        disable_joins: true

      has_many :status_check_responses, class_name: 'MergeRequests::StatusCheckResponse', inverse_of: :merge_request
      has_many :approval_rules, class_name: 'ApprovalMergeRequestRule', inverse_of: :merge_request do
        def applicable_to_branch(branch)
          ActiveRecord::Associations::Preloader.new(
            records: self,
            associations: [
              :users, :group_users, :groups, :scan_result_policy_read, :approval_policy_rule,
              { approval_project_rule: [:users, :groups, :protected_branches] }
            ]
          ).call

          self.select { |rule| rule.applicable_to_branch?(branch) }
        end

        def set_applicable_when_copying_rules(applicable_ids)
          where.not(id: applicable_ids).update_all(applicable_post_merge: false)
          where(id: applicable_ids).update_all(applicable_post_merge: true)
        end
      end
      has_many :applicable_post_merge_approval_rules,
        -> { applicable_post_merge },
        class_name: 'ApprovalMergeRequestRule',
        inverse_of: :merge_request
      has_many :approval_merge_request_rule_sources, through: :approval_rules
      has_many :approval_project_rules, through: :approval_merge_request_rule_sources

      # Merge requests that carry an approval rule of the given report type(s).
      # Uses a correlated EXISTS so the planner probes approval_merge_request_rules
      # per merge request via the merge_request_id index, rather than materialising
      # an instance-wide set of rule merge_request_ids. Combined with each_batch on
      # the (project, opened) relation this stays index-backed regardless of how many
      # open merge requests the project has.
      scope :with_approval_rules_by_report_types, ->(report_types) do
        rules = ::ApprovalMergeRequestRule.arel_table
        where(
          ::ApprovalMergeRequestRule
            .by_report_types(report_types)
            .where(rules[:merge_request_id].eq(arel_table[:id]))
            .arel.exists
        )
      end

      # rubocop:disable Cop/ActiveRecordDependent -- legacy usage
      has_one :merge_train_car, class_name: 'MergeTrains::Car', inverse_of: :merge_request, dependent: :destroy
      # rubocop:enable Cop/ActiveRecordDependent -- legacy usage

      has_one :risk_assessment, class_name: 'MergeRequests::RiskAssessment', inverse_of: :merge_request

      has_many :blocks_as_blocker,
        class_name: 'MergeRequestBlock',
        inverse_of: :blocking_merge_request,
        foreign_key: :blocking_merge_request_id

      has_many :blocks_as_blockee,
        class_name: 'MergeRequestBlock',
        inverse_of: :blocked_merge_request,
        foreign_key: :blocked_merge_request_id

      has_many :blocking_merge_requests, through: :blocks_as_blockee

      has_many :blocked_merge_requests, through: :blocks_as_blocker

      has_many :duo_workflows, class_name: 'Ai::DuoWorkflows::Workflow', inverse_of: :merge_request
      has_many :ai_suggested_reviewers, class_name: 'MergeRequests::AiSuggestedReviewer', inverse_of: :merge_request
      has_many :compliance_violations, class_name: 'MergeRequests::ComplianceViolation'
      has_many :scan_result_policy_violations, class_name: 'Security::ScanResultPolicyViolation'

      has_many :requested_changes,
        class_name: 'MergeRequests::RequestedChange',
        inverse_of: :merge_request
      has_many :change_requesters,
        class_name: 'User',
        through: :requested_changes,
        source: :user

      has_many :scan_result_policy_reads_through_violations,
        through: :scan_result_policy_violations, source: :scan_result_policy_read,
        class_name: 'Security::ScanResultPolicyRead'

      has_many :security_policies_through_violations,
        through: :scan_result_policy_violations, source: :security_policy,
        class_name: 'Security::Policy'

      has_many :scan_result_policy_reads_through_approval_rules,
        through: :approval_rules, source: :scan_result_policy_read,
        class_name: 'Security::ScanResultPolicyRead'

      has_many :running_scan_result_policy_violations, -> { running }, class_name:
        'Security::ScanResultPolicyViolation', inverse_of: :merge_request

      has_many :failed_scan_result_policy_violations, -> { failed }, class_name:
        'Security::ScanResultPolicyViolation', inverse_of: :merge_request

      has_many :merge_request_stage_events, class_name: 'Analytics::CycleAnalytics::MergeRequestStageEvent'
      has_many :approval_policy_merge_request_bypass_events,
        class_name: 'Security::ApprovalPolicyMergeRequestBypassEvent', inverse_of: :merge_request

      # WIP v2 approval rules as part of https://gitlab.com/groups/gitlab-org/-/epics/12955
      has_many :v2_approval_rules_merge_requests, class_name: 'MergeRequests::ApprovalRulesMergeRequest',
        inverse_of: :merge_request
      has_many :v2_approval_rules, through: :v2_approval_rules_merge_requests,
        class_name: 'MergeRequests::ApprovalRule', source: :approval_rule

      has_many :policy_dismissals, class_name: 'Security::PolicyDismissal', inverse_of: :merge_request

      delegate :sha, to: :base_pipeline, prefix: :base_pipeline, allow_nil: true
      delegate :wrapped_approval_rules, :invalid_approvers_rules, to: :approval_state

      accepts_nested_attributes_for :approval_rules, allow_destroy: true
      accepts_nested_attributes_for :v2_approval_rules, allow_destroy: true

      scope :not_merged, -> { where.not(merge_requests: { state_id: ::MergeRequest.available_states[:merged] }) }

      # ARRAY(...) collects the diff ids first, so the planner starts from the head_commit_sha index
      # instead of walking merge_requests by id and probing diffs per row (like the EXISTS
      # fallback in by_commit_sha).
      scope :with_latest_diff_head_sha, ->(sha) do
        diff_ids = ::MergeRequestDiff.by_head_commit_sha(sha).select(:id)

        where('merge_requests.latest_merge_request_diff_id = ANY(ARRAY(?))', diff_ids)
      end
      scope :preload_head_pipeline_and_latest_diff, -> { preload(:head_pipeline, :latest_merge_request_diff) }

      scope :authored_by_dependency_bump_service_account, -> do
        joins(:author).merge(::User.service_accounts).where(users: {
          name: ::DependencyManagement::ProvisionServiceAccountService::SERVICE_ACCOUNT_NAME
        })
      end

      # Unlike Issuable.not_authored, keeps MRs whose author was deleted (author_id NULL).
      scope :not_authored_by_user_id, ->(user_id) { where(arel_table[:author_id].is_distinct_from(user_id)) }

      scope :not_closed_by, ->(user) do
        joins(:metrics).where.not(merge_request_metrics: { latest_closed_by_id: user })
      end

      scope :order_review_time_desc, -> do
        joins(:metrics).reorder(::MergeRequest::Metrics.review_time_field.asc.nulls_last)
      end

      scope :with_code_review_api_entity_associations, ->(preload_diff_files: true) do
        latest_diff = :latest_merge_request_diff
        latest_diff = { latest_merge_request_diff: :merge_request_diff_files } if preload_diff_files

        preload(
          :author, :approved_by_users, :metrics,
          latest_diff, target_project: :namespace, milestone: :project)
      end

      scope :including_merge_train, -> do
        includes(:merge_train_car)
      end

      scope :with_head_pipeline, -> { where.not(head_pipeline_id: nil) }

      scope :for_projects_with_security_policy_project, -> do
        joins('INNER JOIN security_orchestration_policy_configurations ' \
              'ON merge_requests.target_project_id = security_orchestration_policy_configurations.project_id')
      end

      scope :with_applied_scan_result_policies, -> do
        joins(:approval_rules).merge(ApprovalMergeRequestRule.from_scan_result_policy)
      end

      scope :with_policy_bot_comment, ->(project) do
        security_bot = ::Users::Internal.in_organization(project.organization).security_bot

        joins(:notes).merge(
          ::Note
            .authored_by(security_bot)
            .note_starting_with(::Security::ScanResultPolicies::PolicyViolationComment::MESSAGE_HEADER)
        ).distinct
      end

      after_create_commit :create_pending_status_check_responses, if: :allow_external_status_checks?
      after_update :sync_merge_request_compliance_violation, if: :saved_change_to_title?

      def sync_merge_request_compliance_violation
        compliance_violations.update_all(title: title)
      end

      def create_pending_status_check_responses
        return unless diff_head_sha.present?

        ::ComplianceManagement::PendingStatusCheckWorker.perform_async(id, project.id, diff_head_sha)
      end

      def merge_requests_author_approval?
        !!target_project&.merge_requests_author_approval? &&
          !policy_approval_settings.fetch(:prevent_approval_by_author, false)
      end

      def merge_requests_disable_committers_approval?
        !!target_project&.merge_requests_disable_committers_approval? ||
          policy_approval_settings.fetch(:prevent_approval_by_commit_author, false)
      end

      def require_password_to_approve?
        target_project&.require_password_to_approve? ||
          policy_approval_settings.fetch(:require_password_to_approve, false)
      end

      def policy_approval_settings
        return {} if scan_result_policy_violations.empty?

        security_policies_through_violations.reject(&:warn_mode?).reduce({}) do |acc, security_policy|
          settings = security_policy.content['approval_settings'] || {}

          acc.merge!(settings.select { |_, value| value }.symbolize_keys)
        end
      end
      strong_memoize_attr :policy_approval_settings

      def policies_overriding_approval_settings
        overrides = approval_settings_overridden_by_policies

        return overrides if ::Feature.enabled?(:approval_policy_selective_code_owner_removals, project)

        # The setting is inert while the flag is off, so a policy that sets nothing else
        # is not overriding anything users should be told about.
        overrides.filter_map do |policy, settings|
          remaining = settings.except(:remove_code_owner_approvals_with_new_commit)

          [policy, remaining] if remaining.present?
        end.to_h
      end
      strong_memoize_attr :policies_overriding_approval_settings

      def approval_settings_overridden_by_policies
        return {} if scan_result_policy_violations.empty?

        if security_policies_through_violations.any?
          security_policies_through_violations
            # rubocop:disable Layout/LineLength -- not autoformattable
            .select { |policy| !policy.enforcement_type_warn? && policy.content['approval_settings']&.compact_blank.present? }
            # rubocop:enable Layout/LineLength
            .index_with { |policy| policy.content['approval_settings'].compact_blank.symbolize_keys }
        else
          # TODO: Temporary code path without policy details
          # Remove when backfill from https://gitlab.com/gitlab-org/gitlab/-/merge_requests/173714 is finished
          scan_result_policy_reads_through_violations
            .select { |read| read.project_approval_settings.compact_blank.present? }
            .to_h do |read|
              policy = Security::Policy.new(
                security_orchestration_policy_configuration_id: read.security_orchestration_policy_configuration_id,
                policy_index: read.orchestration_policy_idx)
              settings = read.project_approval_settings.compact_blank.symbolize_keys

              [policy, settings]
            end
        end
      end

      # It allows us to finalize the approval rules of merged merge requests
      attr_accessor :finalizing_rules

      # Used to show warning messages when Duo Code Review is attempted without a seat
      attr_accessor :duo_code_review_attempted
    end

    class_methods do
      extend ::Gitlab::Utils::Override

      # This is an ActiveRecord scope in CE
      def with_web_entity_associations
        super.preload(target_project: :invited_groups)
      end

      # This is an ActiveRecord scope in CE
      def with_api_entity_associations
        super.preload(
          :blocking_merge_requests, :scan_result_policy_reads_through_violations,
          :scan_result_policy_reads_through_approval_rules,
          :running_scan_result_policy_violations, :requested_changes,
          :approvals, :approved_by_users, :scan_result_policy_violations,
          applicable_post_merge_approval_rules: [
            :approved_approvers, :group_users, :users, :approval_policy_rule,
            { approval_project_rule: [:protected_branches, :group_users, :users] }
          ],
          approval_rules: [
            :group_users, :users,
            { approval_project_rule: [:group_users, :users] }
          ],
          target_project: [
            :regular_or_any_approver_approval_rules,
            {
              regular_or_any_approver_approval_rules: [
                :group_users, :users
              ]
            },
            :protected_branches,
            { protected_branches: [:squash_option] },
            { group: :saml_provider }
          ]
        )
      end

      def sort_by_attribute(method, *args, **kwargs)
        if method.to_s == 'review_time_desc'
          order_review_time_desc
        else
          super
        end
      end

      # Includes table keys in group by clause when sorting
      # preventing errors in postgres
      #
      # Returns an array of arel columns
      def grouping_columns(sort, use_cte: false)
        grouping_columns = super
        grouping_columns << ::MergeRequest::Metrics.review_time_field if sort.to_s == 'review_time_desc'
        grouping_columns
      end

      # override
      def use_separate_indices?
        true
      end

      override :mergeable_state_checks_by_tier
      def mergeable_state_checks_by_tier
        super.merge(
          trivial: [
            ::MergeRequests::Mergeability::CheckExternalStatusChecksPassedService,
            ::MergeRequests::Mergeability::CheckJiraStatusService
          ],
          light: [
            ::MergeRequests::Mergeability::CheckBlockedByOtherMrsService,
            ::MergeRequests::Mergeability::CheckRequestedChangesService,
            ::MergeRequests::Mergeability::CheckMergeRequestTitleRegexService,
            ::MergeRequests::Mergeability::CheckSecurityPolicyViolationsService
          ],
          heavy: [
            ::MergeRequests::Mergeability::CheckPathLocksService,
            ::MergeRequests::Mergeability::CheckApprovedService,
            ::MergeRequests::Mergeability::CheckSecurityPolicyPipelineStatusService
          ]
        ) { |_tier, ce_checks, ee_checks| ce_checks + ee_checks }
      end

      override :likely_to_fail_first_checks_by_group
      def likely_to_fail_first_checks_by_group
        super.merge(
          likely_light: [
            ::MergeRequests::Mergeability::CheckBlockedByOtherMrsService,
            ::MergeRequests::Mergeability::CheckRequestedChangesService
          ],
          light: [
            ::MergeRequests::Mergeability::CheckExternalStatusChecksPassedService,
            ::MergeRequests::Mergeability::CheckJiraStatusService,
            ::MergeRequests::Mergeability::CheckMergeRequestTitleRegexService,
            ::MergeRequests::Mergeability::CheckSecurityPolicyViolationsService
          ],
          heavy: [
            ::MergeRequests::Mergeability::CheckPathLocksService,
            ::MergeRequests::Mergeability::CheckApprovedService,
            ::MergeRequests::Mergeability::CheckSecurityPolicyPipelineStatusService
          ]
        ) { |_group, ce_checks, ee_checks| ce_checks + ee_checks }
      end
    end

    override :predefined_variables
    def predefined_variables
      super.concat(merge_request_approval_variables)
    end

    override :merge_blocked_by_other_mrs?
    def merge_blocked_by_other_mrs?
      strong_memoize(:merge_blocked_by_other_mrs) do
        blocking_merge_requests_feature_available? &&
          blocking_merge_requests.any? { |mr| !mr.merged? }
      end
    end

    override :read_only_target_project?
    def read_only_target_project?
      ::Import::Sync::Projects::WritePolicy.read_only?(target_project)
    end

    override :skipped_auto_merge_checks
    def skipped_auto_merge_checks(options = {})
      merge_train_strat = ::AutoMergeService::MERGE_TRAIN_STRATEGIES.include?(options[:auto_merge_strategy])

      # Merge trains handle rebasing internally when building the train ref,
      # so the standard rebase check would produce false negatives. The train
      # machinery guarantees the correct merge result regardless of rebase state.
      # See also: `should_be_rebased?` override and `from_train_ref.rb` strategy.
      result = super.merge(skip_rebase_check: merge_train_strat)

      if options[:auto_merge_strategy] == ::AutoMergeService::STRATEGY_MERGE_TRAIN
        # When the pipeline was built on the merge train ref, CI has already
        # validated the merged result - re-checking CI status would be redundant.
        # However, keep the CI check if the MR is already on the train (status
        # may have changed) or if a pipeline is still being created.
        skip_ci_check = !on_train? && diff_head_pipeline&.merge_train_pipeline? && !pipeline_creating?
        result.merge(skip_ci_check: skip_ci_check)
      else
        result
      end
    end

    def on_train?
      merge_train_car&.active?
    end

    def allow_external_status_checks?
      project.licensed_feature_available?(:external_status_checks)
    end

    def can_resolve_with_ai?(user)
      user.present? &&
        conflict_detected? &&
        !for_fork? &&
        ::Gitlab::UserAccess.new(user, container: source_project).can_push_to_branch?(source_branch)
    end

    def can_resolve_discussions_with_ai?(user)
      user.present? &&
        project.duo_features_enabled &&
        project.duo_remote_flows_enabled &&
        !for_fork? &&
        ::Gitlab::UserAccess.new(user, container: source_project).can_push_to_branch?(source_branch)
    end

    def visible_blocking_merge_requests(user)
      Ability.merge_requests_readable_by_user(blocking_merge_requests, user)
    end

    def visible_blocking_merge_request_refs(user)
      visible_blocking_merge_requests(user).map do |mr|
        mr.to_reference(target_project)
      end
    end

    # Unlike +visible_blocking_merge_requests+, this method doesn't include
    # blocking MRs that have been merged. This simplifies output, since we don't
    # need to tell the user that there are X hidden blocking MRs, of which only
    # Y are an obstacle. Pass include_merged: true to override this behaviour.
    def hidden_blocking_merge_requests_count(user, include_merged: false)
      hidden = blocking_merge_requests - visible_blocking_merge_requests(user)

      hidden.delete_if(&:merged?) unless include_merged

      hidden.count
    end

    def enabled_reports
      {
        sast: report_type_enabled?(:sast),
        container_scanning: report_type_enabled?(:container_scanning),
        dast: report_type_enabled?(:dast),
        dependency_scanning: report_type_enabled?(:dependency_scanning) || report_type_enabled?(:cyclonedx),
        license_scanning: report_type_enabled?(:license_scanning),
        coverage_fuzzing: report_type_enabled?(:coverage_fuzzing),
        secret_detection: report_type_enabled?(:secret_detection),
        api_fuzzing: report_type_enabled?(:api_fuzzing)
      }
    end

    def has_security_reports?
      !!diff_head_pipeline&.complete_or_manual_and_has_reports?(::Ci::JobArtifact.security_reports)
    end

    override :has_sast_reports?
    def has_sast_reports?
      super || agentic_sast_reports?
    end

    override :agentic_sast_reports?
    def agentic_sast_reports?
      return super unless ::Security::AgenticAnalyzer.enabled?(project)
      # Every MR page asks this; without a stored agentic scan for the commit, skip the CI lookup.
      return false unless ::Security::AgenticAnalyzer.scan_recorded?(project, diff_head_sha)

      # The agentic analyzer publishes its SAST report on a separate duo_workflow
      # workload pipeline, not on diff_head_pipeline, so the core check misses it.
      has_sast_reports_for?(::Security::AgenticAnalyzer.scan_pipeline_for(project, diff_head_sha))
    end

    def compare_license_scanning_reports(current_user)
      return missing_report_error("license scanning") unless license_scanner_for_diff_head_pipeline.results_available?

      compare_reports(::Ci::CompareLicenseScanningReportsService, current_user)
    end

    def compare_license_scanning_reports_collapsed(current_user)
      return missing_report_error("license scanning") unless license_scanner_for_diff_head_pipeline.results_available?

      compare_reports(
        ::Ci::CompareLicenseScanningReportsCollapsedService,
        current_user,
        'license_scanning',
        additional_params: { license_check: approval_rules.license_compliance.any? }
      )
    end

    def has_metrics_reports?
      !!diff_head_pipeline&.complete_and_has_self_or_descendant_reports?(::Ci::JobArtifact.of_report_type(:metrics))
    end

    def compare_metrics_reports(current_user = nil)
      return missing_report_error("metrics") unless has_metrics_reports?

      compare_reports(::Ci::CompareMetricsReportsService, current_user)
    end

    def synchronize_approval_rules_from_target_project
      return if merged?

      project_rules = linked_report_approver_project_rules.includes(:users, :groups)

      seen_apr_ids = Set.new

      project_rules.find_each do |project_rule|
        next if !::Security::PolicyAvailability.any_available?(project) &&
          project_rule.from_scan_result_policy?

        with_violation = first_for_approval_policy_rule?(project_rule, seen_apr_ids)

        project_rule.apply_report_approver_rules_to(self, with_violation: with_violation) do |rule_attributes|
          rule_attributes[:approvals_required] = 0 if project_rule.from_scan_result_policy?
        end
      end
    end

    # Applicable policy rules missing from the merge request indicate a lost
    # sync, e.g. a retarget whose update hooks never ran:
    # https://gitlab.com/gitlab-org/gitlab/-/issues/601181
    def missing_policy_approval_rules?
      # Rules without an approval_policy_rule are legacy leftovers that policy sync never
      # copies to merge requests, so they would be flagged as missing forever.
      applicable_rules = linked_report_approver_project_rules
        .from_scan_result_policy
        .with_approval_policy_rule
        .includes(:protected_branches, :project)
        .select { |project_rule| project_rule.applies_to_branch?(target_branch) }

      return false if applicable_rules.empty?

      synced_project_rule_ids = approval_rules
        .report_approver
        .joins(:approval_merge_request_rule_source)
        .pluck('approval_merge_request_rule_sources.approval_project_rule_id')

      (applicable_rules.map(&:id) - synced_project_rule_ids).any?
    end

    def linked_report_approver_project_rules
      project_rules = target_project.approval_rules.report_approver

      # Only sync rules that are actively linked to this project.
      # Otherwise, approval rules could be recreated which were just deleted
      # by `#unlink_policy` due to a race.
      linked_rule_ids = target_project.approval_policy_rule_project_links
        .select(:approval_policy_rule_id)

      project_rules.where(approval_policy_rule_id: linked_rule_ids)
        .or(project_rules.where(approval_policy_rule_id: nil))
    end

    def schedule_policy_synchronization
      if project.approval_policy_rules_targeting_commits?
        # We need to make sure to run the merge request worker after hooks were called to
        # get correct commit signatures
        ::Security::ScanResultPolicies::SyncAnyMergeRequestApprovalRulesWorker.perform_async(id)
      end

      if approval_rules.by_report_types([:scan_finding, :license_scanning]).any?
        ::Security::ScanResultPolicies::SyncPreexistingStatesApprovalRulesWorker.perform_async(id)
      end

      pipeline_id = diff_head_pipeline&.id

      if pipeline_id
        ::Ci::SyncReportsToReportApprovalRulesWorker.perform_async(pipeline_id)

        # This is needed here to avoid inconsistent state when the scan result policy is updated after the
        # head pipeline completes and before the merge request is created, we might have inconsistent state.
        ::Security::ScanResultPolicies::SyncMergeRequestApprovalsWorker.perform_async(pipeline_id, id)
        ::Security::UnenforceablePolicyRulesPipelineNotificationWorker.perform_async(pipeline_id)
      elsif !pipeline_creating?
        ::Security::UnenforceablePolicyRulesNotificationWorker.perform_async(id)
      end
    end

    def security_policies_with_branch_exceptions
      approval_rules
        .includes(approval_policy_rule: :security_policy)
        .select(&:branches_exempted_by_policy?)
        .map(&:approval_policy_rule)
        .map(&:security_policy)
        .uniq
    end
    strong_memoize_attr :security_policies_with_branch_exceptions

    def security_policies_with_bypass_settings
      policy_rule_ids = approval_rules.where.not(approval_policy_rule_id: nil).select(:approval_policy_rule_id)

      # A subquery instead of a join, so a policy with several matching rules is returned once.
      project.approval_policies.with_bypass_settings
        .preload(:approval_policy_merge_request_bypass_events)
        .where(id: Security::ApprovalPolicyRule.id_in(policy_rule_ids).select(:security_policy_id))
    end

    def sync_project_approval_rules_for_approval_policy_rules(policy_rules)
      return if merged?

      project_approval_rules = report_approver_project_rules
                        .for_approval_policy_rules(policy_rules)

      apply_report_approver_project_rules(project_approval_rules)
    end

    def sync_project_approval_rules_for_policy_configuration(configuration_id)
      return if merged?

      project_approval_rules = report_approver_project_rules
                      .with_approval_policy_rule
                      .for_policy_configuration(configuration_id)

      apply_report_approver_project_rules(project_approval_rules)
    end

    def finalize_rules
      self.finalizing_rules = true
      yield
      self.finalizing_rules = false
    end

    def reset_required_approvals(approval_rules)
      return if merged?

      seen_apr_ids = Set.new

      approval_rules.filter_map(&:source_rule).filter_map do |rule|
        rule.apply_report_approver_rules_to(self,
          with_violation: first_for_approval_policy_rule?(rule, seen_apr_ids))
      end
    end

    def applicable_approval_rules_for_user(user_id)
      wrapped_approval_rules.select do |rule|
        rule.approvers.pluck(:id).include?(user_id)
      end
    end

    def security_reports_up_to_date?
      project.security_reports_up_to_date_for_ref?(target_branch)
    end

    def audit_details
      title
    end

    def latest_pipeline_for_target_branch
      project.ci_pipelines.order(id: :desc).find_by(ref: target_branch)
    end
    strong_memoize_attr :latest_pipeline_for_target_branch

    def all_target_branch_pipelines
      project.all_pipelines.where(ref: target_branch)
    end

    def latest_comparison_pipeline_with_sbom_reports
      target_branch_comparison_pipelines.find do |pipeline|
        pipeline.self_and_project_descendants.any?(&:has_sbom_reports?)
      end
    end

    def latest_scan_finding_comparison_pipeline
      target_branch_comparison_pipelines.find do |pipeline|
        pipeline.self_and_project_descendants.any?(&:has_security_reports?)
      end
    end
    strong_memoize_attr :latest_scan_finding_comparison_pipeline

    def target_branch_comparison_pipelines
      target_shas = [diff_head_pipeline&.target_sha, diff_base_sha, diff_start_sha].compact
      expanded_shas = target_shas | additional_target_branch_commit_shas_for_comparison
      return [] if expanded_shas.empty?

      begin
        pipelines_by_sha = batch_loaded_recent_target_branch_pipelines_for_shas(expanded_shas).group_by(&:sha)
      # rubocop:disable Database/RescueQueryCanceled -- Temporary fallback until https://gitlab.com/gitlab-org/gitlab/-/work_items/578926 is implemented
      rescue ActiveRecord::QueryCanceled, ActiveRecord::StatementInvalid => e
        ::Gitlab::ErrorTracking.log_exception(e, { merge_request_id: id, comparison_shas: expanded_shas })
        lazy_loaded_recent_target_branch_pipelines_for_shas(target_shas)
      # rubocop:enable Database/RescueQueryCanceled
      else
        expanded_shas.flat_map do |sha|
          pipelines_by_sha[sha] || []
        end
      end
    end
    strong_memoize_attr :target_branch_comparison_pipelines

    def additional_target_branch_commit_shas_for_comparison
      target_project.repository.commits(
        target_branch,
        limit: MAX_CHECKED_ADDITIONAL_SHAS_FOR_SECURITY_REPORT_COMPARISON
      ).map(&:id).uniq
    # These SHAs are optional extra candidates, so an overloaded Gitaly should not fail the whole comparison.
    rescue ::Gitlab::Git::ResourceExhaustedError, ::Gitlab::Git::CommandError => e
      ::Gitlab::ErrorTracking.log_exception(
        e,
        { merge_request_id: id, Labkit::Fields::GL_PROJECT_ID => project_id, target_branch: target_branch }
      )
      []
    end
    strong_memoize_attr :additional_target_branch_commit_shas_for_comparison

    # Should only be used as a fallback if `batch_loaded_recent_target_branch_pipelines_for_shas`
    # fails or times out. This will fire a query for each SHA when iterating through
    # the results, making it less efficient but more reliable for SHA sets with many pipelines.
    def lazy_loaded_recent_target_branch_pipelines_for_shas(shas)
      shas.lazy.flat_map do |sha|
        target_branch_pipelines_for(sha: sha)
          .order(id: :desc)
          .limit(MAX_CHECKED_PIPELINES_FOR_SECURITY_REPORT_COMPARISON)
      end
    end

    # Retrieves the most recent pipelines for each target commit SHA, limited to
    # MAX_CHECKED_PIPELINES_FOR_SECURITY_REPORT_COMPARISON pipelines per SHA for performance.
    # Uses a LATERAL join to avoid ranking every row, making smaller sorts per SHA.
    def batch_loaded_recent_target_branch_pipelines_for_shas(shas)
      sha_values = shas.map { |sha| "(#{::Ci::Pipeline.connection.quote(sha)})" }.join(', ')
      sources = ::Enums::Ci::Pipeline.ci_sources.values.compact.join(',')

      lateral_query = <<~SQL
        SELECT ranked_pipelines.*
        FROM (VALUES #{sha_values}) AS commits(sha)
        JOIN LATERAL (
          SELECT p_ci_pipelines.*
          FROM p_ci_pipelines
          WHERE p_ci_pipelines.sha = commits.sha
            AND p_ci_pipelines.project_id = #{project.id}
            AND (p_ci_pipelines.source IN (#{sources}) OR p_ci_pipelines.source IS NULL)
            AND p_ci_pipelines.ref = #{::Ci::Pipeline.connection.quote(target_branch)}
          ORDER BY p_ci_pipelines.id DESC
          LIMIT #{MAX_CHECKED_PIPELINES_FOR_SECURITY_REPORT_COMPARISON}
        ) ranked_pipelines ON TRUE
        ORDER BY ranked_pipelines.sha, ranked_pipelines.id DESC
      SQL

      ::Ci::Pipeline.find_by_sql(lateral_query)
    end

    def diff_head_pipeline?(pipeline)
      pipeline.source_sha == diff_head_sha || pipeline.sha == diff_head_sha
    end

    override :can_suggest_reviewers?
    def can_suggest_reviewers?
      open? && modified_paths.any?
    end

    override :suggested_reviewer_users
    def suggested_reviewer_users
      return ::User.none unless predictions && predictions.suggested_reviewers.is_a?(Hash)

      usernames = Array.wrap(suggested_reviewers["reviewers"])
      return ::User.none if usernames.empty?

      # Preserve the original order of suggested usernames
      join_sql = ::MergeRequest.sanitize_sql_array(
        [
          'JOIN UNNEST(ARRAY[?]::varchar[]) WITH ORDINALITY AS t(username, ord) USING(username)',
          usernames
        ]
      )

      project.authorized_users.with_state(:active).human
        .joins(Arel.sql(join_sql))
        .order('t.ord')
    end

    def merge_train
      target_project.merge_train_for(target_branch)
    end

    override :should_be_rebased?
    def should_be_rebased?
      # Skip rebase check for merge train strategies since the train handles rebasing
      merge_train_strategy = ::AutoMergeService::MERGE_TRAIN_STRATEGIES.include?(auto_merge_strategy)

      return false if merge_train_strategy
      return false if merge_train_car&.on_ff_train?

      super
    end

    override :comparison_base_pipeline
    def comparison_base_pipeline(service_class, report_type = nil)
      return super(service_class) unless security_comparison?(service_class)

      security_report_comparison(report_type).base_pipeline
    end

    # Head pipeline for the MR security comparison of `report_type`
    # (see Security::AgenticAnalyzer::MergeRequestComparison).
    def security_comparison_head_pipeline(report_type)
      security_report_comparison(report_type).head_pipeline
    end

    # Agentic analyzer scan pipelines compared together with the head and base pipelines
    # (see Security::AgenticAnalyzer::MergeRequestComparison).
    def security_comparison_additional_pipeline_ids(report_type)
      security_report_comparison(report_type).additional_pipeline_ids
    end

    def blocking_merge_requests_feature_available?
      project.licensed_feature_available?(:blocking_merge_requests)
    end

    def notify_approvers
      approvers = wrapped_approval_rules.flat_map(&:approvers).uniq

      ::NotificationService.new.added_as_approver(approvers, self)
    end

    def reviewer_requests_changes_feature
      project.feature_available?(:requested_changes_block_merge_request)
    end

    def has_changes_requested?
      requested_changes.any?
    end

    override :create_requested_changes
    def create_requested_changes(user)
      requested_changes.find_or_create_by(project_id: project_id, user_id: user.id)
    end

    override :destroy_requested_changes
    def destroy_requested_changes(user)
      requested_changes.where(user_id: user.id).delete_all
    end

    def requested_changes_for_users(user_ids)
      requested_changes.where(user_id: user_ids)
    end

    def ai_review_merge_request_allowed?(user)
      ::Gitlab::Duo::CodeReview.enabled?(user: user, container: project) && Ability.allowed?(user, :create_note, self)
    end

    def ai_reviewable_diff_files(patch_only: false)
      # `expanded: true` because a collapsed file's `diff_lines` is empty, which silently
      # drops every review comment on it (no diff line for the comment to anchor to).
      # `raw_diff_files` skips the highlight cache: reviews only read `diff_lines`, and decoding
      # every file's highlighted lines from Redis dominates allocations on large merge requests.
      diffs(expanded: true).raw_diff_files.select(&(patch_only ? :ai_reviewable_patch? : :ai_reviewable?))
    end

    def temporarily_unapproved?(memoize: false)
      approval_state.temporarily_unapproved?(memoize: memoize)
    end

    override :squash_option
    def squash_option
      protected_branch = target_project.protected_branches.then do |protected_branches|
        if protected_branches.loaded?
          protected_branches.find { |protected_branch| protected_branch.name == target_branch }
        else
          protected_branches.find_by(name: target_branch)
        end
      end

      return protected_branch.squash_option if protected_branch&.squash_option

      super
    end
    strong_memoize_attr :squash_option

    def policy_bot_comment
      notes
        .authored_by(::Users::Internal.in_organization(project.organization).security_bot)
        .note_starting_with(Security::ScanResultPolicies::PolicyViolationComment::MESSAGE_HEADER).first
    end

    def approval_rules_editable_by?(user)
      return unless user

      project.can_override_approvers? &&
        (user.can_admin_all_resources? ||
        (assigned_or_authored_by_with_access?(user) ||
         project.team.member?(user, ::Gitlab::Access::MAINTAINER)))
    end

    # Whether Duo Code Review can be started for this merge request at all. Shared by the
    # request-side funnel (EE::MergeRequests::BaseService#request_duo_code_review) and by
    # Ai::DuoWorkflows::CodeReview::StartReviewWorker, which re-checks at execution time
    # because the merge request can change between enqueue and execution.
    def duo_code_review_startable?
      return false if merged? || closed?

      # merge_request_diff never returns nil - it falls back to an unpersisted
      # MergeRequestDiff - so the persisted? check is what distinguishes "diffs are still
      # being generated" from "ready to review".
      diff = merge_request_diff
      return false unless diff.persisted?

      !diff.empty?
    end

    # Sidekiq delivers at least once, so a redelivered StartReviewWorker job must not stack
    # a second review on a live one. Keyed on workflow status rather than the progress note,
    # because a cancelled flow leaves its note behind until TimeoutWorker clears it.
    #
    # Deliberately a positive list: it matches what CleanStuckWorkflowsService can recover,
    # so a flow stuck in any other state cannot block this merge request forever.
    def duo_code_review_in_flight?
      ::Ai::DuoWorkflows::Workflow
        .for_merge_request(self)
        .with_workflow_definition(::Ai::Catalog::FoundationalFlow.code_review_v1.foundational_flow_reference)
        .without_messaging_sessions
        .with_status(:created, :running)
        .exists?
    end

    override :duo_code_review_progress_note
    def duo_code_review_progress_note
      notes
        .joins(:system_note_metadata)
        .find_by(system_note_metadata: { action: 'duo_code_review_started' })
    end

    def duo_code_review_last_reviewed_head_sha(review_bot)
      return unless review_bot

      last_review = reviews.where(author: review_bot).order(id: :desc).first

      last_review&.notes&.non_legacy_diff_notes&.first&.original_position&.head_sha
    end

    def preserve_open_policy_dismissals!
      return unless merged?
      return unless target_branch == target_project.default_branch

      policy_dismissals.open.find_each(&:preserve!)
    end

    def duo_vulnerability_fix?
      source_branch.start_with?(DUO_VULNERABILITY_FIX_BRANCH_PREFIX)
    end

    def dependency_management_auto_remediation?
      vulnerability_merge_request_links.exists? &&
        source_branch.start_with?("#{::DependencyManagement::SecurityUpdate::Request::BRANCH_PREFIX}/")
    end

    def created_by_agentic_vr?
      vulnerability_merge_request_links.exists? && duo_vulnerability_fix?
    end

    def dependency_management_mr?
      return false unless source_branch&.start_with?(
        ::DependencyManagement::SecurityUpdate::Request::BRANCH_PREFIX
      )

      return false unless author&.service_account?

      author.name == ::DependencyManagement::ProvisionServiceAccountService::SERVICE_ACCOUNT_NAME
    end

    def duo_dependency_bump_breaking_changes_available?
      return false unless dependency_management_mr?

      target_project.duo_dependency_bump_breaking_changes_available?
    end

    def duo_code_reviewed?
      duo_code_review_bot = ::Users::Internal.in_organization(organization.id).duo_code_review_bot

      return false unless duo_code_review_bot

      merge_request_reviewers
        .where(state: ::MergeRequests::UpdateReviewerStateService::REVIEWER_ASSIGNMENT_STATES)
        .exists?(user_id: duo_code_review_bot.id)
    end

    private

    override :report_type_enabled?
    def report_type_enabled?(report_type)
      return super unless report_type == :license_scanning

      license_scanner_for_diff_head_pipeline.has_data?
    end

    def license_scanner_for_diff_head_pipeline
      ::Gitlab::LicenseScanning.scanner_for_pipeline(project, diff_head_pipeline,
        self_and_project_descendants: ::Feature.enabled?(:include_child_pipeline_sboms_in_pipeline_licenses, project))
    end

    # The recheck states are only ever entered from cannot_be_merged, so the
    # last known truth is "this MR has conflicts" and we are merely re-verifying it.
    def conflict_detected?
      cannot_be_merged? || cannot_be_merged_recheck? || cannot_be_merged_rechecking?
    end

    def assigned_or_authored_by_with_access?(user)
      assignee_or_author?(user) &&
        project.team.member?(user, ::Gitlab::Access::DEVELOPER)
    end

    def security_comparison?(service_class)
      service_class == ::Vulnerabilities::CompareSecurityReportsService
    end

    def security_report_comparison(report_type)
      strong_memoize_with(:security_report_comparison, report_type) do
        ::Security::AgenticAnalyzer::MergeRequestComparison.new(self, report_type)
      end
    end

    def merge_request_approval_variables
      return unless approval_feature_available?

      ::Gitlab::Ci::Variables::Collection.new.tap do |variables|
        variables.append(
          key: 'CI_MERGE_REQUEST_APPROVED',
          lazy: true,
          value: -> {
            ::Gitlab::Ci::Variables::Preloader::MergeRequest.new(self).preload
            result = approved?
            result.to_s if result
          }
        )
      end
    end
    strong_memoize_attr :merge_request_approval_variables

    def report_approver_project_rules
      target_project.approval_rules.report_approver
    end

    def apply_report_approver_project_rules(project_rules)
      seen_apr_ids = Set.new

      project_rules.includes(:users, :groups).find_each do |project_rule|
        project_rule.apply_report_approver_rules_to(self,
          with_violation: first_for_approval_policy_rule?(project_rule, seen_apr_ids))
      end
    end

    def first_for_approval_policy_rule?(project_rule, seen_apr_ids)
      apr_id = project_rule.approval_policy_rule_id
      apr_id.nil? || seen_apr_ids.add?(apr_id).present?
    end
  end
end
