# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class SyncAnyMergeRequestRulesService
      include Gitlab::Utils::StrongMemoize
      include ::Security::ScanResultPolicies::PolicyViolationCommentGenerator
      include ::Security::ScanResultPolicies::PolicyLogger

      REPORT_TYPE = :any_merge_request

      def initialize(merge_request)
        @merge_request = merge_request
        @violations = Security::SecurityOrchestrationPolicies::UpdateViolationsService.new(merge_request)
        @violations_by_policy = {}
        @full_commit_shas_by_policy = {}
      end

      def execute
        return if merge_request.merged?

        sync_required_approvals
      end

      private

      attr_reader :merge_request, :violations, :violations_by_policy

      delegate :project, to: :merge_request, private: true

      def sync_required_approvals
        related_sources = related_approval_policy_sources

        # Callers enqueue only for projects with policy rules targeting commits, so no reads here
        # means they are missing or being rebuilt, and nothing gets enforced on this merge request.
        if related_sources.empty?
          log_message('Skipping any_merge_request rules: no scan_result_policy_reads targeting commits',
            scan_result_policy_reads_count: 0)
          return
        end

        violated_sources, unviolated_sources = evaluate_policy_violations(related_sources)
        violated_rules, unviolated_rules = rules_for_violated_policies(violated_sources)
        violated_rules, unviolated_rules = update_required_approvals(violated_rules, unviolated_rules)

        log_message('Evaluating any_merge_request rules from approval policies',
          scan_result_policy_reads_count: related_sources.size,
          violated_policies_count: violated_sources.size,
          violated_approval_rules_count: violated_rules.size,
          unviolated_approval_rules_count: unviolated_rules.size)

        log_violated_rules(violated_rules)
        unviolated_policy_rule_ids = unviolated_rules.filter_map(&:approval_policy_rule_id)
        violated_sources = violated_sources.reject do |s|
          unviolated_policy_rule_ids.include?(s.approval_policy_rule_id)
        end
        violations.add(
          violated_sources,
          unviolated_sources + unviolated_rules.map(&:approval_policy_source)
        )
        save_violation_data(violated_sources)
        violations.execute
        generate_policy_bot_comment(merge_request)
      end

      def evaluate_policy_violations(approval_policy_sources)
        unsigned_commits = merge_request.commits(load_from_gitaly: true)
                                         .select { |commit| !commit.has_signature? }.map(&:id)
        violated, unviolated = approval_policy_sources.partition do |source|
          targets_any_commits = source.commits_any?
          targets_unsigned_commits = source.commits_unsigned? && unsigned_commits.any?
          next false unless targets_any_commits || targets_unsigned_commits

          policy_affected_by_target_branch?(source).tap do |violated|
            next unless violated

            if targets_any_commits
              violations_by_policy[source.id] = true
            else
              violations_by_policy[source.id] =
                Security::ScanResultPolicyViolation.trim_violations(unsigned_commits)
              @full_commit_shas_by_policy[source.id] = unsigned_commits
            end
          end
        end
        [violated, unviolated]
      end

      def policy_branch_service
        ::Security::SecurityOrchestrationPolicies::PolicyBranchesService.new(project: project)
      end
      strong_memoize_attr :policy_branch_service

      def policy_affected_by_target_branch?(policy_source)
        rule = policy_source.resolved_approval_policy_rule&.content&.deep_symbolize_keys
        return true if rule.blank?

        return false if branch_excepted?(rule[:branch_exceptions])

        # If this merge request already has approval rules for the policy, they were filtered for the target branch
        # when created, so we can skip the (Gitaly-backed) branch computation below.
        return true if approval_rules_for_policies(any_merge_request_rules, [policy_source]).any?

        affected_branches = policy_branch_service.scan_result_branches([rule])
        affected_branches.include? merge_request.target_branch
      end

      def branch_excepted?(exceptions)
        exceptions&.any? do |exception|
          case exception
          when String then merge_request.target_branch == exception
          when Hash then merge_request.target_branch == exception[:name] && exception[:full_path] == project.full_path
          end
        end
      end

      def any_merge_request_rules
        merge_request.approval_rules.any_merge_request
      end
      strong_memoize_attr :any_merge_request_rules

      def rules_for_violated_policies(violated_policies)
        approval_rules_for_target_branch = any_merge_request_rules.applicable_to_branch(merge_request.target_branch)

        violated_rules = approval_rules_for_policies(approval_rules_for_target_branch, violated_policies)
        unviolated_rules = any_merge_request_rules - violated_rules

        [violated_rules, unviolated_rules]
      end

      def update_required_approvals(violated_rules, unviolated_rules)
        updated_violated_rules = merge_request.reset_required_approvals(violated_rules)

        # A rule with no approval_policy_rule_id can't be matched against a policy source in
        # `approval_rules_for_policies`, so it ends up here by default rather than by being
        # confirmed unviolated. Zeroing it would silently disable its approval requirement
        # (see https://gitlab.com/gitlab-org/gitlab/-/issues/617882).
        zeroable_rules = unviolated_rules.select(&:policy_rule_id_present?)
        ApprovalMergeRequestRule.remove_required_approved(zeroable_rules) if zeroable_rules.any?

        [updated_violated_rules, unviolated_rules]
      end

      def approval_rules_for_policies(approval_rules, policy_sources)
        policy_ids = policy_sources.filter_map(&:approval_policy_rule_id)
        approval_rules.select { |rule| policy_ids.include?(rule.approval_policy_rule_id) }
      end

      def log_violated_rules(rules)
        return unless rules.any?

        rules.each do |approval_rule|
          log_message('Updating MR approval rule',
            reason: 'any_merge_request rule violated',
            approval_rule_id: approval_rule.id,
            approval_rule_name: approval_rule.name
          )
        end
      end

      def log_message(message, **attributes)
        log_policy_evaluation('update_approvals', message,
          project: project, merge_request_id: merge_request.id,
          merge_request_iid: merge_request.iid, **attributes)
      end

      def save_violation_data(violated_sources)
        violated_sources.each do |source|
          violations.add_violation(source, REPORT_TYPE, { commits: violations_by_policy[source.id] })

          full_commit_shas = @full_commit_shas_by_policy[source.id]
          violations.add_violation_detail_data(source, full_commit_shas: full_commit_shas) if full_commit_shas
        end
      end

      def related_approval_policy_sources
        related_scan_result_policy_reads.map do |scan_result_policy_read|
          Security::ApprovalPolicySource.new(
            project: project,
            action_idx: scan_result_policy_read.action_idx,
            scan_result_policy_read: scan_result_policy_read,
            approval_policy_rule: scan_result_policy_read.approval_policy_rule
          )
        end
      end

      def related_scan_result_policy_reads
        project.scan_result_policy_reads
               .targeting_commits
               .preload_approval_policy_rule
      end
    end
  end
end
