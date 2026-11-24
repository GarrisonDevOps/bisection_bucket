# frozen_string_literal: true

module SCA
  class LicenseCompliance
    include ::Gitlab::Utils::StrongMemoize
    include ::Gitlab::SPDX::ExpressionEvaluator

    LicenseNotFoundError = Class.new(StandardError)

    MULTI_LICENSE_NODE_TYPES = (::Gitlab::SPDX::ExpressionEvaluator::COMPOUND_NODE_TYPES - %i[plus]).freeze

    # ExpressionEvaluator leaf context: a leaf matches when its policy has this classification.
    LeafContext = Data.define(:policies, :classification)
    private_constant :LeafContext

    SORT_DIRECTION = {
      asc: ->(items) { items },
      desc: ->(items) { items.reverse }
    }.with_indifferent_access

    # `user` scopes artifact reads (nil = guest, i.e. public artifacts only). Internal
    # callers pass `LicenseScanning::UNSCOPED` (the default) to read everything.
    def initialize(
      project, pipeline, target_branch = nil, user = ::Gitlab::LicenseScanning::UNSCOPED,
      self_and_project_descendants: false)
      @project = project
      @pipeline = pipeline
      @target_branch = target_branch
      @scanner = ::Gitlab::LicenseScanning.scanner_for_pipeline(project, pipeline, user,
        self_and_project_descendants: self_and_project_descendants)
    end

    def policies
      unclassified_policies.merge(known_policies).sort.map(&:last)
    end
    strong_memoize_attr :policies

    def find_policies(detected_only: false, classification: [], sort: { by: :name, direction: :asc })
      classifications = Array(classification || [])
      matching_policies = policies.reject do |policy|
        (detected_only && policy.dependencies.none?) ||
          (classifications.present? && !policy.classification.in?(classifications))
      end
      sort_items(items: matching_policies, by: sort&.dig(:by), direction: sort&.dig(:direction))
    end

    def latest_build_for_default_branch
      return if pipeline.blank?

      scanner.latest_build_for_default_branch
    end

    def diff_with(other)
      other_report = other.license_scanning_report
      denied_policies_from_other_report = denied_license_policies_from_report(other_report)

      license_scanning_report_diff(other_report).transform_values do |reported_licenses|
        reported_licenses.map do |reported_license|
          build_policy_with_denied_licenses(denied_policies_from_other_report, reported_license)
        end
      end
    end

    def license_scanning_report
      scanner.report
    end
    strong_memoize_attr :license_scanning_report

    private

    def license_scanning_report_diff(other_report)
      license_scanning_report.diff_with_including_new_dependencies_for_unchanged_licenses(other_report,
        include_version: false)
    end

    attr_reader :project, :pipeline, :target_branch, :scanner

    def license_policies
      return SoftwareLicensePolicy.none if project.blank?

      project
        .software_license_policies
        .including_scan_result_policy_read
        .including_approval_policy_rule
        .unreachable_limit
    end
    strong_memoize_attr :license_policies

    # Constructs license to policy map for licenses from `software_license_policies`
    # directly. They are sorted by `classification` to return denied licenses first.
    def direct_license_policies
      build_direct_license_policies(license_policies)
    end
    strong_memoize_attr :direct_license_policies

    def license_types_policies
      license_policies.select { |policy| license_types_policy?(policy) }
    end
    strong_memoize_attr :license_types_policies

    def license_types_policies_by_rule
      license_types_policies.group_by(&:approval_policy_rule)
    end
    strong_memoize_attr :license_types_policies_by_rule

    def licenses_policies
      license_policies.reject { |policy| license_types_policy?(policy) }
    end
    strong_memoize_attr :licenses_policies

    def build_direct_license_policies(policies)
      policies.sort_by(&:classification).to_h do |policy|
        software_license = Gitlab::SPDX::Catalogue.latest_active_licenses.find do |license|
          license.id == policy.software_license_spdx_identifier
        end

        license = policy.custom_software_license || software_license

        if license.blank?
          Gitlab::ErrorTracking.track_exception(LicenseNotFoundError.new,
            license_spdx_id: policy.software_license_spdx_identifier,
            project_id: policy.project_id)

          next [nil, nil]
        end

        reported_license = reported_license_by_license_model(license)
        [license.canonical_id, build_policy(reported_license, policy, approval_status(policy))]
      end.compact
    end

    def license_types_policy?(policy)
      policy.approval_policy_rule&.license_types.present?
    end

    def approval_status(policy)
      return policy.approval_status if policy_applies_to_branch?(policy)

      'allowed'
    end

    # Denies any report license not already resolved by direct_license_policies, either via
    # the allow-list default-deny behavior, or by evaluating a compound SPDX expression,
    # which a deny-list-only license_types policy can still deny through the unknown fallback,
    # and a `licenses` deny-list rule can deny through SPDX deny-list semantics.
    def denied_license_policies
      denied_license_policies_from_report(license_scanning_report)
    end
    strong_memoize_attr :denied_license_policies

    def known_policies
      return {} if project.blank?

      direct_license_policies.merge(denied_license_policies)
    end
    strong_memoize_attr :known_policies

    def unclassified_policies
      license_scanning_report.licenses.map do |reported_license|
        next if policy_from_licenses(known_policies, reported_license)

        [reported_license.canonical_id, build_policy(reported_license, nil)]
      end.compact.to_h
    end

    def denied_license_policies_from_report(report)
      report.licenses.map do |reported_license|
        next if policy_from_licenses(direct_license_policies, reported_license)
        next deny_listed_expression_policy(reported_license) unless license_expression_evaluable?(reported_license)

        allowed, classification_reason = classify_license_expression(reported_license)
        approval_status = allowed ? 'allowed' : 'denied'
        [reported_license.canonical_id,
          build_policy(reported_license, nil, approval_status, classification_reason: classification_reason)]
      end.compact.to_h
    end

    # The default-deny-anything-unmatched behavior only applies when an allow-list policy
    # exists. A deny-list-only license_types policy still needs its multi-license expression
    # evaluated, since the unknown fallback is the only thing that decides its status.
    def license_expression_evaluable?(reported_license)
      return true if exclusion_allowed_policy_exists?
      return false if license_types_policies.empty?

      split_license_types_fallback?(parsed_license_node(reported_license).type)
    end

    # Without an allow-list, a compound expression is denied when any `licenses` rule denies it under
    # SPDX deny-list semantics (AND: any operand denied, OR: every operand denied), as
    # Security::MergeRequestApprovalPolicies::LicenseExpressionChecker does for each rule.
    def deny_listed_expression_policy(reported_license)
      return unless Feature.enabled?(:license_expression_checker, project)
      return if licenses_policies.empty?

      node = parsed_license_node(reported_license)
      return unless MULTI_LICENSE_NODE_TYPES.include?(node.type)

      denied = licenses_rules_direct_license_policies.any? do |policies|
        evaluate_violation(node, LeafContext.new(policies: policies, classification: 'denied'))
      end
      return unless denied

      [reported_license.canonical_id, build_policy(reported_license, nil, 'denied')]
    end

    def licenses_policies_by_rule
      licenses_policies
        .group_by(&:approval_policy_rule)
        .values
    end
    strong_memoize_attr :licenses_policies_by_rule

    def licenses_rules_direct_license_policies
      licenses_policies_by_rule.map { |policies| build_direct_license_policies(policies) }
    end
    strong_memoize_attr :licenses_rules_direct_license_policies

    def exclusion_allowed_policy_exists?
      license_policies.exclusion_allowed.exists?
    end
    strong_memoize_attr :exclusion_allowed_policy_exists?

    # Reported licenses can be compound SPDX expressions ("Apache-2.0 OR MPL-2.0"). Operands are
    # evaluated individually, except under a license_types policy, which falls back to `unknown`
    # instead (matching Security::ScanResultPolicies::LicenseViolationChecker). Returns
    # [allowed, classification_reason], where the reason is only set on the fallback branch.
    def classify_license_expression(reported_license)
      node = parsed_license_node(reported_license)
      return [false, nil] unless ::Gitlab::SPDX::ExpressionEvaluator::COMPOUND_NODE_TYPES.include?(node.type)

      unless split_license_types_fallback?(node.type)
        return [evaluate(node, LeafContext.new(policies: direct_license_policies, classification: 'allowed')), nil]
      end

      [license_types_allow_unknown? && licenses_allow_expression?(node), :license_types_unknown_fallback]
    end

    def parsed_license_node(reported_license)
      expression = reported_license.id.presence || reported_license.name
      ::Gitlab::SPDX::ExpressionParser.new(expression).parse.node
    end

    def split_license_types_fallback?(node_type)
      license_types_policies.present? &&
        MULTI_LICENSE_NODE_TYPES.include?(node_type) &&
        Feature.enabled?(:license_types_unknown_expression_fallback, project)
    end

    # Each license_types-sourced approval policy rule is evaluated independently, then combined
    # as "denied wins", mirroring how LicenseViolationChecker#execute evaluates one rule at a
    # time rather than flattening every rule's licenses into a single lookup.
    def license_types_allow_unknown?
      return true if license_types_policies.empty?

      license_types_policies_by_rule.all? { |rule, policies| rule_allows_unknown?(rule, policies) }
    end
    strong_memoize_attr :license_types_allow_unknown?

    # An unlisted `unknown` means denied under an allow-list rule, but allowed under a
    # deny-list one, mirroring LicenseViolationChecker#execute's match_on_inclusion_license
    # branches.
    def rule_allows_unknown?(approval_policy_rule, policies)
      unknown_policy = build_direct_license_policies(policies)['unknown']
      return unknown_policy.classification == 'allowed' if unknown_policy

      approval_policy_rule.match_on_inclusion_license == true
    end

    # Allow-list `licenses` rules are merged; each deny-list rule (no allowed rows) is evaluated
    # on its own with SPDX deny-list semantics, as LicenseExpressionChecker does.
    def licenses_allow_expression?(node)
      licenses_allow_list_allows_expression?(node) && !licenses_deny_lists_deny_expression?(node)
    end

    def licenses_allow_list_allows_expression?(node)
      return true if licenses_allow_list_policies.empty?

      evaluate(node, LeafContext.new(policies: licenses_allow_list_policies, classification: 'allowed'))
    end

    def licenses_deny_lists_deny_expression?(node)
      return false unless Feature.enabled?(:license_expression_checker, project)

      licenses_deny_list_rules_policies.any? do |policies|
        evaluate_violation(node, LeafContext.new(policies: policies, classification: 'denied'))
      end
    end

    # [allow-list rules, deny-list rules]. Uses the stored classification, not approval_status:
    # rules that do not apply to the target branch report every row as allowed.
    def licenses_rules_by_list_type
      licenses_policies_by_rule.partition { |policies| policies.any?(&:allowed?) }
    end
    strong_memoize_attr :licenses_rules_by_list_type

    def licenses_allow_list_policies
      build_direct_license_policies(licenses_rules_by_list_type.first.flatten)
    end
    strong_memoize_attr :licenses_allow_list_policies

    def licenses_deny_list_rules_policies
      licenses_rules_by_list_type.last.map { |policies| build_direct_license_policies(policies) }
    end
    strong_memoize_attr :licenses_deny_list_rules_policies

    def evaluate_leaf(value, context)
      policy = context.policies[value] || context.policies[value.to_s.downcase]

      policy&.classification == context.classification
    end

    def build_policy_with_denied_licenses(denied_policies, reported_license)
      direct_license_policy = policy_from_licenses(direct_license_policies, reported_license)
      return build_policy(reported_license, direct_license_policy, nil) if direct_license_policy

      policy_from_report = policy_from_licenses(denied_policies, reported_license)
      build_policy(reported_license, policy_from_report, policy_from_report&.approval_status,
        classification_reason: policy_from_report&.classification_reason)
    end

    def policy_applies_to_branch?(policy)
      approval_rule = policy.approval_policy_rule
      return false unless approval_rule && target_branch

      approval_rule.policy_applies_to_target_branch?(target_branch, project)
    end

    # When the license found in the report doesn't match any license
    # of the SPDX License List, we need to find it by name explicitly.
    def reported_license_by_license_model(software_license)
      license_scanning_report[software_license.canonical_id] ||
        license_scanning_report.by_license_name(software_license.name&.downcase)
    end

    def policy_from_licenses(licenses_map, license)
      licenses_map[license.id] || licenses_map[license&.name&.downcase]
    end

    def build_policy(reported_license, software_license_policy, approval_status = nil, classification_reason: nil)
      ::SCA::LicensePolicy.new(reported_license, software_license_policy, approval_status,
        classification_reason: classification_reason)
    end

    def sort_items(items:, by:, direction:, available_attributes: ::SCA::LicensePolicy::ATTRIBUTES)
      attribute = available_attributes[by] || available_attributes[:name]
      direction = SORT_DIRECTION[direction] || SORT_DIRECTION[:asc]
      direction.call(items.sort_by { |item| attribute.call(item) })
    end
  end
end
