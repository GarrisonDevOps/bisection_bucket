# frozen_string_literal: true

module Security
  class Policy < ApplicationRecord
    include Auditable
    include Security::Policies::VulnerabilityManagement
    include Gitlab::Utils::StrongMemoize

    self.table_name = 'security_policies'
    self.inheritance_column = :_type_disabled

    DEFAULT_ENFORCEMENT_TYPE = 'enforce'
    ENFORCEMENT_TYPE_WARN = 'warn'
    PIPELINE_EXECUTION_SCHEDULE_POLICY_TYPE = 'pipeline_execution_schedule_policy'

    POLICY_CONTENT_FIELDS = {
      approval_policy: %i[actions approval_settings fallback_behavior policy_tuning bypass_settings enforcement_type],
      scan_execution_policy: %i[actions skip_ci no_pipeline],
      pipeline_execution_policy: %i[
        content pipeline_config_strategy suffix skip_ci variables_override no_pipeline enforce_on_child_pipelines
      ],
      vulnerability_management_policy: %i[actions],
      pipeline_execution_schedule_policy: %i[content schedules variables_override],
      dependency_firewall_policy: %i[rules name enabled enforcement_type bypass_settings]
    }.freeze
    APPROVAL_MERGE_REQUEST_RULES_BATCH_SIZE = 1000
    APPROVAL_RULES_DELETE_BATCH_SIZE = 1000

    belongs_to :security_orchestration_policy_configuration, class_name: 'Security::OrchestrationPolicyConfiguration'
    belongs_to :security_policy_management_project, class_name: 'Project'
    has_many :approval_policy_rules, class_name: 'Security::ApprovalPolicyRule', foreign_key: 'security_policy_id',
      inverse_of: :security_policy
    has_many :undeleted_approval_policy_rules, -> { undeleted },
      class_name: 'Security::ApprovalPolicyRule', foreign_key: 'security_policy_id',
      inverse_of: :security_policy
    has_many :scan_execution_policy_rules, class_name: 'Security::ScanExecutionPolicyRule',
      foreign_key: 'security_policy_id', inverse_of: :security_policy
    has_many :vulnerability_management_policy_rules, class_name: 'Security::VulnerabilityManagementPolicyRule',
      foreign_key: 'security_policy_id', inverse_of: :security_policy
    has_many :dependency_firewall_policy_rules, class_name: 'Security::DependencyFirewallPolicyRule',
      foreign_key: 'security_policy_id', inverse_of: :security_policy
    has_many :undeleted_dependency_firewall_policy_rules, -> { undeleted },
      class_name: 'Security::DependencyFirewallPolicyRule', foreign_key: 'security_policy_id',
      inverse_of: :security_policy
    has_many :security_policy_project_links, class_name: 'Security::PolicyProjectLink',
      foreign_key: :security_policy_id, inverse_of: :security_policy
    has_one :security_pipeline_execution_policy_config_link,
      class_name: 'Security::PipelineExecutionPolicyConfigLink',
      foreign_key: :security_policy_id, inverse_of: :security_policy

    has_many :projects, through: :security_policy_project_links

    has_many :security_pipeline_execution_project_schedules,
      class_name: 'Security::PipelineExecutionProjectSchedule',
      foreign_key: :security_policy_id, inverse_of: :security_policy
    has_many :scan_execution_project_schedules,
      class_name: 'Security::ScanExecutionProjectSchedule',
      foreign_key: :security_policy_id, inverse_of: :security_policy
    has_many :approval_policy_merge_request_bypass_events,
      class_name: 'Security::ApprovalPolicyMergeRequestBypassEvent',
      foreign_key: :security_policy_id, inverse_of: :security_policy
    has_many :policy_dismissals,
      class_name: 'Security::PolicyDismissal',
      foreign_key: :security_policy_id, inverse_of: :security_policy
    has_many :scheduled_pipeline_execution_policy_test_runs,
      class_name: 'Security::ScheduledPipelineExecutionPolicyTestRun',
      foreign_key: :security_policy_id, inverse_of: :security_policy
    has_many :policy_schedule_pipelines,
      class_name: 'Security::PolicySchedulePipeline',
      foreign_key: :security_policy_id, inverse_of: :security_policy
    has_many :schedule_pipelines, through: :policy_schedule_pipelines, source: :pipeline

    enum :type, {
      approval_policy: 0,
      scan_execution_policy: 1,
      pipeline_execution_policy: 2,
      vulnerability_management_policy: 3,
      pipeline_execution_schedule_policy: 4,
      dependency_firewall_policy: 5
    }, prefix: true

    validates :security_orchestration_policy_configuration_id,
      uniqueness: { scope: %i[type policy_index] }

    validates :scope, json_schema: { filename: "security_policy_scope" }
    validates :scope, exclusion: { in: [nil] }

    validates :content, json_schema: { filename: "approval_policy_content" }, if: :type_approval_policy?
    validates :content, json_schema: { filename: "pipeline_execution_policy_content" },
      if: :type_pipeline_execution_policy?
    validates :content, json_schema: { filename: "pipeline_execution_schedule_policy_content" },
      if: :type_pipeline_execution_schedule_policy?
    validates :content, json_schema: { filename: "scan_execution_policy_content" }, if: :type_scan_execution_policy?
    validates :content, json_schema: { filename: "vulnerability_management_policy_content" },
      if: :type_vulnerability_management_policy?
    validates :content, json_schema: { filename: "dependency_firewall_policy_content", size_limit: 64.kilobytes },
      if: :type_dependency_firewall_policy?
    validate :dependency_firewall_feature_flag_enabled, if: :type_dependency_firewall_policy?

    validates :content, exclusion: { in: [nil] }
    validates :description, length: { maximum: Gitlab::Database::MAX_TEXT_SIZE_LIMIT }

    scope :for_rule_schedule, ->(rule_schedule) {
      type_scan_execution_policy
        .for_policy_configuration(rule_schedule.security_orchestration_policy_configuration_id)
        .undeleted
        .enabled
        .order_by_index
        .offset(rule_schedule.policy_index)
        .limit(1)
    }
    scope :undeleted, -> { where('policy_index >= 0') }
    scope :deleted, -> { where('policy_index < 0') }
    scope :order_by_index, -> { order(policy_index: :asc) }
    scope :enabled, -> { where(enabled: true) }
    scope :for_policy_index, ->(policy_index) { where(policy_index: policy_index) }
    scope :with_active_projects, -> do
      active_links = Security::PolicyProjectLink
        .joins(:project)
        .merge(Project.non_archived)
        .where(Security::PolicyProjectLink.arel_table[:security_policy_id].eq(arel_table[:id]))

      where_exists(active_links)
    end
    scope :for_policy_configuration, ->(policy_configuration) {
      where(security_orchestration_policy_configuration: policy_configuration)
    }
    scope :for_policy_configuration_ids, ->(policy_configuration_ids) {
      where(security_orchestration_policy_configuration_id: policy_configuration_ids)
    }

    def self.policy_identifiers_with_active_projects(config_ids)
      for_policy_configuration_ids(config_ids)
        .with_active_projects
        .pluck(:security_orchestration_policy_configuration_id, :type, :policy_index) # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- bounded by the per-configuration policy limits (max 20 per type)
    end
    scope :for_projects, ->(project_ids) {
      joins(:security_policy_project_links)
        .where(security_policy_project_links: { project_id: project_ids })
        .distinct
    }
    scope :for_configuration_id_and_name_tuples, ->(tuples) do
      break none if tuples.empty?

      composite_key = Arel::Nodes::Grouping.new([
        arel_table[:security_orchestration_policy_configuration_id],
        arel_table[:name]
      ])

      tuple_values = tuples.map do |id, name|
        Arel::Nodes::Grouping.new([
          Arel::Nodes.build_quoted(id),
          Arel::Nodes.build_quoted(name)
        ])
      end

      where(composite_key.in(tuple_values))
    end

    scope :for_custom_role, ->(custom_role_id) do
      where("content->'actions' @> ?", [{ role_approvers: [custom_role_id] }].to_json)
    end

    scope :with_bypass_settings, -> do
      where("#{table_name}.content->'bypass_settings' IS NOT NULL")
        .where("#{table_name}.content->'bypass_settings' <> ?", '{}')
    end

    scope :with_warn_mode, -> { where("content->>'enforcement_type' = ?", ENFORCEMENT_TYPE_WARN) }
    scope :without_warn_mode, -> { where("content->>'enforcement_type' IS DISTINCT FROM ?", ENFORCEMENT_TYPE_WARN) }

    scope :including_security_policy_management_project, -> { includes(:security_policy_management_project) }

    scope :preload_pipeline_execution_config_link, -> { preload(:security_pipeline_execution_policy_config_link) }
    scope :preload_approval_policy_rules, -> { preload(:undeleted_approval_policy_rules) }
    scope :preload_dependency_firewall_policy_rules, -> { preload(:undeleted_dependency_firewall_policy_rules) }
    scope :preload_configuration_namespace_and_project, -> {
      preload(security_orchestration_policy_configuration: [:namespace, :project])
    }

    scope :block_branch_modification,
      -> { where("content -> 'approval_settings' ->> 'block_branch_modification' = 'true'") }
    scope :prevent_pushing_and_force_pushing,
      -> { where("content -> 'approval_settings' ->> 'prevent_pushing_and_force_pushing' = 'true'") }
    scope :prevent_editing_approval_rules,
      -> { where("content -> 'approval_settings' ->> 'prevent_editing_approval_rules' = 'true'") }

    scope :with_enrichment_filters, -> do
      joins(:approval_policy_rules)
        .merge(Security::ApprovalPolicyRule.with_enrichment_filters)
        .distinct
    end

    scope :execution_policies, -> { type_scan_execution_policy.or(type_pipeline_execution_policy).enabled.undeleted }

    delegate :namespace?, :namespace, :project?, :project, :source, to: :security_orchestration_policy_configuration

    def self.checksum(policy_hash)
      Digest::SHA256.hexdigest(policy_hash.to_json)
    end

    def self.attributes_from_policy_hash(policy_type, policy_hash, policy_configuration)
      # NOTE: We don't include `metadata` here because it contains internal information.
      {
        type: policy_type,
        name: policy_hash[:name],
        description: policy_hash[:description],
        enabled: policy_hash[:enabled],
        scope: policy_hash.fetch(:policy_scope, {}),
        content: policy_hash.slice(*POLICY_CONTENT_FIELDS[policy_type]),
        checksum: checksum(policy_hash),
        security_policy_management_project_id: policy_configuration.security_policy_management_project_id
      }.compact
    end

    def self.rule_attributes_from_rule_hash(policy_type, rule_hash, policy_configuration)
      Security::PolicyRule.for_policy_type(policy_type).attributes_from_rule_hash(rule_hash, policy_configuration)
    end

    def self.upsert_policy(policy_type, policies, policy_hash, policy_index, policy_configuration)
      policy = policies.find_or_initialize_by(policy_index: policy_index, type: policy_type)
      policy.update!(attributes_from_policy_hash(policy_type, policy_hash, policy_configuration))

      if policy.supports_policy_rules?
        Array.wrap(policy_hash[:rules]).map.with_index do |rule_hash, rule_index|
          policy.upsert_rule(rule_index, rule_hash)
        end
      end

      policy.update_pipeline_execution_policy_config_link!
      policy
    end

    def self.skip_unsupported_rule?(policy_type, rule_hash, policy_configuration)
      return false unless policy_type == :dependency_firewall_policy

      type = rule_hash[:type].to_s
      return true unless Security::DependencyFirewallPolicyRule.types.key?(type)

      case type
      when 'age'
        !::Security::DependencyFirewall::Availability.age_rules_enabled?(policy_configuration.source)
      when 'package_version'
        !::Security::DependencyFirewall::Availability.package_version_rules_enabled?(policy_configuration.source)
      else
        false
      end
    end

    def self.next_deletion_index
      (maximum("ABS(policy_index)") || 0) + 1
    end

    def self.soft_delete_all!(policies)
      return if policies.empty?

      transaction do
        max_index = policies.first.security_orchestration_policy_configuration
          .security_policies.next_deletion_index

        policies.each_with_index do |policy, index|
          policy.update_columns(policy_index: -(max_index + index), enabled: false)
        end
      end
    end

    def has_enrichment_filters?
      approval_policy_rules.with_enrichment_filters.exists?
    end

    def link_project!(project)
      transaction do
        security_policy_project_links.for_project(project).first_or_create!
        link_policy_rules_project!(project)

        if type_pipeline_execution_schedule_policy?
          # Newly introduced columns will be written by https://gitlab.com/gitlab-org/gitlab/-/merge_requests/180714
          # security_pipeline_execution_project_schedules.for_project(project).first_or_create!
        end
      end
    end

    def unlink_project!(project)
      transaction do
        security_policy_project_links.for_project(project).delete_all
        security_pipeline_execution_project_schedules.for_project(project).delete_all
        unlink_policy_rules_project!(project)
      end
    end

    def deleted?
      policy_index < 0
    end

    def linked_to_project?(project)
      security_policy_project_links.for_project(project).exists?
    end

    # At most one link per project (unique index), so the limit never truncates
    def linked_project_ids(project_ids)
      return [] if project_ids.blank?

      security_policy_project_links.for_project(project_ids).limit(project_ids.size).pluck(:project_id)
    end

    def update_project_approval_policy_rule_links(project, created_rules, deleted_rules)
      transaction do
        unlink_policy_rules_project!(project, deleted_rules)
        link_policy_rules_project!(project, created_rules)
      end
    end

    def update_pipeline_execution_policy_config_link!
      return unless type_pipeline_execution_policy?

      security_pipeline_execution_policy_config_link&.destroy!

      config_project = Project.in_organization(source.organization_id)
        .find_by_full_path(pipeline_execution_ci_config['project'])
      create_security_pipeline_execution_policy_config_link!(project: config_project) if config_project
    end

    def upsert_rule(rule_index, rule_hash)
      return if self.class.skip_unsupported_rule?(type.to_sym, rule_hash, security_orchestration_policy_configuration)

      rule = Security::PolicyRule
        .for_policy_type(type.to_sym)
        .find_or_initialize_by(security_policy_id: id, rule_index: rule_index)

      rule.update!(
        self.class.rule_attributes_from_rule_hash(type.to_sym, rule_hash, security_orchestration_policy_configuration)
      )

      rule
    end

    def to_policy_hash
      {
        name: name,
        description: description,
        enabled: enabled,
        policy_scope: scope.deep_symbolize_keys,
        metadata: metadata
      }.merge(content_by_type)
    end

    def rules_hash
      rules.map(&:typed_content).map(&:deep_symbolize_keys)
    end

    def all_rules
      if type_approval_policy?
        approval_policy_rules
      elsif type_scan_execution_policy?
        scan_execution_policy_rules
      elsif type_vulnerability_management_policy?
        vulnerability_management_policy_rules
      elsif type_dependency_firewall_policy?
        dependency_firewall_policy_rules
      end
    end

    def rules
      if type_approval_policy? && association(:undeleted_approval_policy_rules).loaded?
        return undeleted_approval_policy_rules
      end

      Array.wrap(all_rules&.undeleted)
    end

    def max_rule_index
      all_rules&.maximum("ABS(rule_index)") || 0
    end

    def next_rule_index
      rules.empty? ? 0 : (rules.maximum(:rule_index) + 1)
    end

    def scope_applicable?(project)
      strong_memoize_with(:scope_applicable, project) do
        policy_scope_checker = Security::SecurityOrchestrationPolicies::PolicyScopeChecker.new(project: project)
        policy_scope_checker.security_policy_applicable?(self)
      end
    end

    def framework_ids_from_scope
      # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- pluck is used for hash
      Array.wrap(scope_hash[:compliance_frameworks]).pluck(:id).uniq
      # rubocop:enable Database/AvoidUsingPluckWithoutLimit
    end

    def scope_hash
      scope.deep_symbolize_keys
    end
    strong_memoize_attr :scope_hash

    def policy_scope
      Security::PolicyScope.new(scope_hash)
    end
    strong_memoize_attr :policy_scope

    def delete_approval_policy_rules
      # Links first: the merge request sync locks link rows before rule rows, so this
      # transaction must take them in the same order to avoid deadlocking against it.
      delete_approval_policy_rule_project_links
      delete_approval_rules
      delete_policy_violations
      delete_software_license_policies

      approval_policy_rules.delete_all(:delete_all)
    end

    # Reads go before approval_project_rules: the FK cascade drops each rule with its read in one
    # statement, so an interrupted run can't leave a read whose rule is gone (which CreateService
    # never recreates). See https://gitlab.com/gitlab-org/gitlab/-/issues/625031
    def delete_approval_policy_rules_for_project(project, rules)
      delete_scan_result_policy_violations_for_project(project, rules)
      delete_software_license_policies_for_project(project, rules)
      delete_scan_result_policy_reads_for_project(project, rules)
      delete_approval_merge_request_rules_for_project(project, rules)
      delete_approval_project_rules_for_project(project, rules)
    end

    def delete_software_license_policies_for_project(project, rules)
      project.software_license_policies.each_batch do |batch|
        batch.where(approval_policy_rule_id: rules).delete_all
      end
    end

    # TODO: Will be removed with https://gitlab.com/gitlab-org/gitlab/-/issues/504296
    def delete_scan_result_policy_reads_for_project(project, rules)
      project.scan_result_policy_reads.for_approval_policy_rules(rules).delete_all
    end

    def delete_scan_execution_policy_rules
      scan_execution_policy_rules.delete_all(:delete_all)
    end

    def delete_security_pipeline_execution_project_schedules
      security_pipeline_execution_project_schedules.each_batch do |batch|
        batch.delete_all
      end
    end

    def edit_path
      return if name.blank?

      id = CGI.escape(name)
      if namespace?
        Gitlab::Routing.url_helpers.edit_group_security_policy_url(namespace, id: id, type: type)
      else
        Gitlab::Routing.url_helpers.edit_project_security_policy_url(project, id: id, type: type)
      end
    end

    def pipeline_execution_ci_config
      content&.dig('content', 'include', 0)
    end

    def policy_content
      content.deep_symbolize_keys
    end
    strong_memoize_attr :policy_content

    def enforcement_type
      defined_enforcement_type || DEFAULT_ENFORCEMENT_TYPE
    end

    def enforcement_type_warn?
      enforcement_type == ENFORCEMENT_TYPE_WARN
    end
    alias_method :warn_mode?, :enforcement_type_warn?

    def enforced_scans
      metadata.fetch('enforced_scans', [])
    end

    def enforced_scans=(scans)
      metadata['enforced_scans'] = scans
    end

    def bypass_settings
      if type_dependency_firewall_policy?
        return Security::DependencyFirewallPolicies::BypassSettings.new(policy_content[:bypass_settings])
      end

      Security::ScanResultPolicies::BypassSettings.new(policy_content[:bypass_settings])
    end
    strong_memoize_attr :bypass_settings

    def approval_policy
      return unless type_approval_policy?

      Security::ScanResultPolicies::ApprovalPolicy.new(self)
    end
    strong_memoize_attr :approval_policy

    def scan_execution_policy
      return unless type_scan_execution_policy?

      Security::ScanExecutionPolicies::ScanExecutionPolicy.new(self)
    end
    strong_memoize_attr :scan_execution_policy

    def pipeline_execution_policy
      return unless type_pipeline_execution_policy?

      Security::PipelineExecutionPolicies::PipelineExecutionPolicy.new(self)
    end
    strong_memoize_attr :pipeline_execution_policy

    def vulnerability_management_policy
      return unless type_vulnerability_management_policy?

      Security::VulnerabilityManagementPolicies::VulnerabilityManagementPolicy.new(self)
    end
    strong_memoize_attr :vulnerability_management_policy

    def pipeline_execution_schedule_policy
      return unless type_pipeline_execution_schedule_policy?

      Security::PipelineExecutionSchedulePolicies::PipelineExecutionSchedulePolicy.new(self)
    end
    strong_memoize_attr :pipeline_execution_schedule_policy

    def dependency_firewall_policy
      return unless type_dependency_firewall_policy?

      Security::DependencyFirewallPolicies::DependencyFirewallPolicy.new(self)
    end
    strong_memoize_attr :dependency_firewall_policy

    # Position among enabled scan execution policies, which is how rule schedules index them
    def rule_schedule_index
      return unless type_scan_execution_policy? && enabled? && !deleted?

      self.class.type_scan_execution_policy
        .for_policy_configuration(security_orchestration_policy_configuration_id)
        .enabled
        .for_policy_index(0...policy_index)
        .count
    end
    strong_memoize_attr :rule_schedule_index

    def supports_policy_rules?
      Security::PolicyRule::SUPPORTED_POLICY_TYPES.include?(type.to_sym)
    end

    def policy_tuning
      Security::ScanResultPolicies::PolicyTuning.new(policy_content[:policy_tuning])
    end
    strong_memoize_attr :policy_tuning

    def security_report_time_window
      policy_tuning.security_report_time_window
    end

    def create_merge_request_bypass_event!(project:, user:, reason:, merge_request:)
      approval_policy_merge_request_bypass_events.create!(
        project: project,
        user: user,
        reason: reason,
        merge_request: merge_request
      )
    end

    def merge_request_bypassed?(merge_request)
      return false unless type_approval_policy?

      if association(:approval_policy_merge_request_bypass_events).loaded?
        approval_policy_merge_request_bypass_events.any? { |e| e.merge_request_id == merge_request.id }
      else
        approval_policy_merge_request_bypass_events.where(merge_request: merge_request).exists?
      end
    end

    def merge_request_bypass_allowed?(merge_request, user)
      return false unless type_approval_policy?
      return false if bypass_settings.bypass_actors_empty?

      bot_bypass_allowed?(user) || user_bypass_allowed?(merge_request, user)
    end

    private

    def delete_approval_project_rules_for_project(project, rules)
      security_orchestration_policy_configuration.approval_project_rules.for_project(project.id)
        .each_batch do |batch|
          batch.for_approval_policy_rules(rules).delete_all
        end
    end

    def delete_approval_merge_request_rules_for_project(project, rules)
      # Materialized so the planner reads only the project's rows; with the other filters inline it
      # walks the configuration-wide (configuration, policy rule, id) index instead.
      project_rules = Gitlab::SQL::CTE.new(
        :project_approval_merge_request_rules,
        ApprovalMergeRequestRule.for_project(project.id)
          .select(:id, :merge_request_id, :security_orchestration_policy_configuration_id, :approval_policy_rule_id),
        materialized: true
      )

      rules_to_delete = ApprovalMergeRequestRule
        .with(project_rules.to_arel)
        .from(project_rules.alias_to(ApprovalMergeRequestRule.arel_table))
        .for_policy_configuration(security_orchestration_policy_configuration_id)
        .for_approval_policy_rules(rules)
        .for_unmerged_merge_requests

      loop do
        ids = rules_to_delete
          .limit(APPROVAL_MERGE_REQUEST_RULES_BATCH_SIZE)
          .pluck(ApprovalMergeRequestRule.arel_table[:id])
        break if ids.empty?

        ApprovalMergeRequestRule.id_in(ids).delete_all
      end
    end

    def delete_scan_result_policy_violations_for_project(project, rules)
      project.scan_result_policy_violations.each_batch do |batch|
        batch.where(approval_policy_rule_id: rules).delete_all
      end
    end

    def dependency_firewall_feature_flag_enabled
      return if ::Security::DependencyFirewall::Availability.access_enabled?(source)

      errors.add(:base, 'dependency_firewall_access feature flag is disabled')
    end

    def bot_bypass_allowed?(user)
      Security::ScanResultPolicies::BotBypassChecker.new(
        bypass_settings: bypass_settings, user: user
      ).bypass_allowed?
    end

    def user_bypass_allowed?(merge_request, user)
      Security::ScanResultPolicies::UserBypassChecker.new(
        bypass_settings: bypass_settings, project: merge_request.project, current_user: user
      ).bypass_scope.present?
    end

    def content_by_type
      content_hash = content.deep_symbolize_keys.slice(*POLICY_CONTENT_FIELDS[type.to_sym])

      return content_hash unless supports_policy_rules?

      content_hash.merge(rules: rules_hash)
    end

    def defined_enforcement_type
      content&.dig('enforcement_type')
    end
    strong_memoize_attr :defined_enforcement_type

    def link_policy_rules_project!(project, policy_rules = approval_policy_rules.undeleted)
      return if !type_approval_policy? || policy_rules.empty?

      Security::ApprovalPolicyRuleProjectLink.insert_all(
        policy_rules.map { |policy_rule| { approval_policy_rule_id: policy_rule.id, project_id: project.id } },
        unique_by: [:approval_policy_rule_id, :project_id]
      )
    end

    def unlink_policy_rules_project!(project, policy_rules = approval_policy_rules)
      return if !type_approval_policy? || policy_rules.empty?

      Security::ApprovalPolicyRuleProjectLink.for_project(project).for_policy_rules(policy_rules).delete_all
    end

    def delete_approval_policy_rule_project_links
      delete_in_batches(
        Security::ApprovalPolicyRuleProjectLink.where(approval_policy_rule_id: approval_policy_rules.select(:id))
      )
    end

    # Reads only this policy's rows through the (configuration, policy rule, id) index,
    # not every rule of the configuration.
    def delete_approval_rules
      policy_configuration = security_orchestration_policy_configuration
      rule_ids = Security::ApprovalPolicyRule.where(security_policy_id: id).ids

      delete_project_rules_in_batches(
        policy_configuration.approval_project_rules.where(approval_policy_rule_id: rule_ids))

      # Merged rows stay, so walk them by id per rule instead of re-reading them in every batch.
      rule_ids.each do |rule_id|
        policy_configuration.approval_merge_request_rules.where(approval_policy_rule_id: rule_id)
          .each_batch(of: APPROVAL_RULES_DELETE_BATCH_SIZE) do |batch|
          batch.for_unmerged_merge_requests.delete_all
        end
      end
    end

    def delete_project_rules_in_batches(rules)
      loop do
        ids = rules.limit(APPROVAL_RULES_DELETE_BATCH_SIZE).pluck(:id)
        break if ids.empty?

        ApprovalProjectRule.id_in(ids).delete_all
      end
    end

    def delete_policy_violations
      delete_in_batches(
        Security::ScanResultPolicyViolation.where(approval_policy_rule_id: approval_policy_rules.select(:id))
      )
    end

    def delete_software_license_policies
      delete_in_batches(SoftwareLicensePolicy.where(approval_policy_rule_id: approval_policy_rules.select(:id)))
    end

    def delete_in_batches(relation)
      relation.each_batch do |batch|
        batch.delete_all
      end
    end
  end
end
