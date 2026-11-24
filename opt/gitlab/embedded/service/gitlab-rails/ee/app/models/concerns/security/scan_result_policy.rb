# frozen_string_literal: true

module Security
  module ScanResultPolicy
    extend ActiveSupport::Concern
    include ::Gitlab::Utils::StrongMemoize

    # Maximum limit that can be set via ApplicationSetting
    POLICIES_LIMIT = 20

    APPROVERS_LIMIT = 300
    APPROVERS_ACTIONS_LIMIT = 5

    APPROVAL_RULES_BATCH_SIZE = 5000
    APPROVAL_RULES_DELETE_BATCH_SIZE = 1000

    POLICY_TYPE_NAME = 'Merge request approval policy'
    SCAN_FINDING = 'scan_finding'
    LICENSE_SCANNING = 'license_scanning'
    LICENSE_FINDING = 'license_finding'
    ANY_MERGE_REQUEST = 'any_merge_request'
    REQUIRE_APPROVAL = 'require_approval'
    SEND_BOT_MESSAGE = 'send_bot_message'

    ALLOWED_ROLES = %w[developer maintainer owner].freeze
    VALID_EPSS_SCORE_OPERATORS = %i[greater_than less_than].freeze

    def self.epss_score_valid?(epss_score)
      return false unless epss_score.is_a?(Hash) && epss_score.present?

      epss_score[:operator]&.to_sym&.in?(VALID_EPSS_SCORE_OPERATORS) && epss_score[:value].is_a?(Numeric)
    end

    included do
      has_many :scan_result_policy_reads,
        class_name: 'Security::ScanResultPolicyRead',
        foreign_key: 'security_orchestration_policy_configuration_id',
        inverse_of: :security_orchestration_policy_configuration
      has_many :approval_merge_request_rules,
        foreign_key: 'security_orchestration_policy_configuration_id',
        inverse_of: :security_orchestration_policy_configuration
      has_many :approval_project_rules,
        foreign_key: 'security_orchestration_policy_configuration_id',
        inverse_of: :security_orchestration_policy_configuration

      def delete_scan_result_policy_reads
        self.class.transaction do
          # Links first: the merge request sync locks link rows before rule rows, so this
          # transaction must take them in the same order to avoid deadlocking against it.
          delete_approval_policy_rule_project_links
          delete_scan_finding_rules
          delete_software_license_policies
          delete_policy_violations

          delete_in_batches(scan_result_policy_reads)
        end
      end

      def delete_approval_policy_rule_project_links
        policy_rule_ids = Security::ApprovalPolicyRule
          .where(security_policy_id: security_policies.select(:id))
          .select(:id)

        # Not delete_in_batches: the links table has no updated_at for its order hint.
        Security::ApprovalPolicyRuleProjectLink
          .where(approval_policy_rule_id: policy_rule_ids)
          .each_batch { |batch| batch.delete_all }
      end

      # License policies and violations are resolved through the reads, so they go first. Reads go
      # before approval_project_rules so the FK cascade drops each rule with its read in one statement.
      # MR rules go before the reads: a retry finds the configuration through the reads or project rules.
      def delete_scan_result_policy_rules_for_project(project)
        delete_merge_request_rules_for_project(project.id)
        delete_software_license_policies_for_project(project)
        delete_policy_violations_for_project(project)
        delete_scan_result_policy_reads_for_project(project.id)
        delete_scan_finding_rules_for_project(project.id)
      end

      def delete_scan_result_policy_reads_for_project(project_id)
        scan_result_policy_reads.where(project_id: project_id).delete_all
      end

      def delete_scan_finding_rules
        delete_in_batches(approval_project_rules)
        delete_merge_request_rules
      end

      def delete_merge_request_rules
        approval_merge_request_rules.each_batch(of: APPROVAL_RULES_BATCH_SIZE) do |batch|
          batch.for_unmerged_merge_requests.delete_all
        end
      end

      def delete_scan_finding_rules_for_project(project_id)
        delete_in_batches(approval_project_rules.where(project_id: project_id))
      end

      def delete_merge_request_rules_for_project(project_id)
        # Keyset over the project's merge requests so each statement is bounded and no row is read twice.
        MergeRequest.of_projects(project_id)
          .each_batch(column: :iid, of: APPROVAL_RULES_DELETE_BATCH_SIZE) do |merge_requests|
          approval_merge_request_rules.for_unmerged_merge_requests(merge_requests).delete_all
        end
      end

      def delete_software_license_policies_for_project(project)
        delete_in_batches(
          project
            .software_license_policies
            .where(scan_result_policy_read: scan_result_policy_reads.for_project(project))
        )
      end

      def delete_policy_violations_for_project(project)
        # scan_result_policy_violations does not store security_orchestration_policy_configuration_id
        # so we need to scope them through scan_resul_policy_reads in order to delete through policy_configuration
        delete_in_batches(
          Security::ScanResultPolicyViolation
            .where(scan_result_policy_read: scan_result_policy_reads.for_project(project))
        )
      end

      def applicable_scan_result_policies_with_real_index(project)
        active_policies_count = 0
        active_policy_index = 0
        policy_scope_checker = Security::SecurityOrchestrationPolicies::PolicyScopeChecker.new(project: project)

        scan_result_policies.each_with_index do |policy, index|
          next unless policy[:enabled]

          active_policies_count += 1
          break if active_policies_count > approval_policies_limit
          next unless policy_scope_checker.policy_applicable?(policy, configuration: self)

          yield(policy, index, active_policy_index)
          active_policy_index += 1
        end
      end

      def active_scan_result_policies
        scan_result_policies&.select { |config| config[:enabled] }&.first(approval_policies_limit)
      end

      def approval_policies_limit
        limit_service.approval_policies_per_configuration_limit
      end

      def applicable_scan_result_policies_for_project(project)
        strong_memoize_with(:applicable_scan_result_policies_for_project, project) do
          policy_scope_checker = ::Security::SecurityOrchestrationPolicies::PolicyScopeChecker.new(project: project)
          active_scan_result_policies.select do |policy|
            policy_scope_checker.policy_applicable?(policy, configuration: self)
          end
        end
      end

      def scan_result_policies
        policy_by_type(:approval_policy).map.with_index do |policy, index|
          policy.merge(type: 'approval_policy', policy_index: index)
        end
      end

      def delete_in_batches(relation)
        relation.each_batch(order_hint: :updated_at) do |batch|
          delete_batch(batch)
        end
      end

      def delete_batch(batch)
        batch.delete_all
      end

      private

      def delete_software_license_policies
        Security::ScanResultPolicyRead
          .where(security_orchestration_policy_configuration_id: id)
          .each_batch(order_hint: :updated_at) do |batch|
          delete_in_batches(SoftwareLicensePolicy.where(scan_result_policy_id: batch.select(:id)))
        end
      end

      def delete_policy_violations
        Security::ScanResultPolicyRead
          .where(security_orchestration_policy_configuration_id: id)
          .each_batch(order_hint: :updated_at) do |batch|
          delete_in_batches(Security::ScanResultPolicyViolation.where(scan_result_policy_id: batch.select(:id)))
        end
      end
    end

    # Ids of users named as approvers in any active approval policy, ignoring policy scope.
    def active_scan_result_policies_user_approver_ids
      actions = active_scan_result_policies.to_a
        .flat_map { |policy| Array(policy[:actions]) }
        .select { |action| action[:type] == REQUIRE_APPROVAL }
      usernames = actions.flat_map { |action| Array(action[:user_approvers]) }

      ids = actions.flat_map { |action| Array(action[:user_approvers_ids]) }
      ids += User.by_username(usernames).pluck_primary_key if usernames.any?
      ids
    end
    strong_memoize_attr :active_scan_result_policies_user_approver_ids
  end
end
