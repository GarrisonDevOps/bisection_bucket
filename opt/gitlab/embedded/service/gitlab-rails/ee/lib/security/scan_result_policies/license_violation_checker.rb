# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class LicenseViolationChecker
      include Gitlab::SPDX::ExpressionParsing

      UNKNOWN_LICENSE_NAME = Gitlab::LicenseScanning::PackageLicenses::UNKNOWN_LICENSE[:name]

      MULTI_LICENSE_NODE_TYPES = (Gitlab::SPDX::ExpressionEvaluator::COMPOUND_NODE_TYPES - %i[plus]).freeze

      def initialize(project, report, target_branch_report)
        @project = project
        @report = report
        @target_branch_report = target_branch_report
      end

      ## Checks if a policy rule violates the following conditions:
      ##   - If license_states has `newly_detected`, check for newly detected dependency
      ##     with license type violating the policy.
      ##   - If match_on_inclusion_license is false, any detected licenses that does not match
      ##     the licenses from `license_types` should require approval
      def execute(approval_policy_source)
        comparison_report = approval_policy_source.newly_detected? ? report : target_branch_report

        software_license_policies = software_license_policies(approval_policy_source)
        licenses_from_policy = extend_from_report(comparison_report, software_license_policies)
        licenses_from_report = join_ids_and_names(
          comparison_report.licenses.filter_map(&:id), normalize_license_names(comparison_report.license_names)
        )

        license_ids, license_names = licenses_to_check(approval_policy_source)
        license_names = normalize_license_names(license_names)

        if approval_policy_source.match_on_inclusion_license
          all_denied_licenses = licenses_from_policy
          policy_denied_license_names = all_denied_licenses & licenses_from_report
          violates_license_policy = violates_db_licenses?(software_license_policies, license_ids, license_names.to_set)
        else
          # when match_on_inclusion_license is false, only the licenses mentioned in the policy are allowed
          all_denied_licenses = (licenses_from_report - licenses_from_policy).uniq
          comparison_licenses = join_ids_and_names(license_ids, license_names)
          policy_denied_license_names = (comparison_licenses - licenses_from_policy).uniq
          violates_license_policy = policy_denied_license_names.present?
        end

        if violates_license_policy
          denied_licenses_with_dependencies = licenses_with_dependencies(comparison_report, policy_denied_license_names)
        end

        # when there are no license violations, but new dependency with denied licenses is added, require approval
        if approval_policy_source.newly_detected?
          new_license_dependency_map = new_dependencies_with_denied_licenses(all_denied_licenses)
          denied_licenses_with_dependencies = new_license_dependency_map if new_license_dependency_map.present?
        end

        denied_licenses_with_dependencies
      end

      private

      attr_reader :project, :report, :target_branch_report

      def software_license_policies(approval_policy_source)
        scope = project.software_license_policies.including_custom_license

        if approval_policy_source.approval_policy_rule_id.present?
          scope.for_approval_policy_rule(approval_policy_source.approval_policy_rule_id)
        else
          scope.for_scan_result_policy_read(approval_policy_source.scan_result_policy_id)
        end
      end

      def violates_db_licenses?(software_license_policies, ids, names)
        spdx_ids_for_license_names = SoftwareLicensePolicy.latest_active_licenses_by_name(names).pluck(:id) # rubocop:disable CodeReuse/ActiveRecord -- Not AR object
        spdx_ids = (ids + spdx_ids_for_license_names).to_set

        policies = software_license_policies.select do |policy|
          spdx_ids.include?(policy.spdx_identifier) || names.include?(policy.custom_software_license&.name)
        end

        policies.present?
      end

      def licenses_to_check(approval_policy_source)
        only_newly_detected = approval_policy_source.license_states == [ApprovalProjectRule::NEWLY_DETECTED]

        if only_newly_detected
          diff = target_branch_report.diff_with(report)
          license_names = diff[:added].map(&:name)
          license_ids = diff[:added].filter_map(&:id)
        elsif approval_policy_source.newly_detected?
          license_names = report.license_names
          license_ids = report.licenses.filter_map(&:id)
        else
          license_names = target_branch_report.license_names
          license_ids = target_branch_report.licenses.filter_map(&:id)
        end

        [license_ids, license_names]
      end

      def join_ids_and_names(ids, names)
        (ids + names).compact.uniq
      end

      def normalize_license_names(names)
        names.map { |name| normalize_license_name(name) }
      end

      def normalize_license_name(name)
        falls_back_to_unknown?(name) ? UNKNOWN_LICENSE_NAME : name
      end

      def falls_back_to_unknown?(name)
        license_types_unknown_expression_fallback_enabled? && multi_license_expression?(name)
      end

      def multi_license_expression?(name)
        MULTI_LICENSE_NODE_TYPES.include?(parse_expression(name).node.type)
      end

      def licenses_matching_name_or_id(comparison_report, licenses)
        comparison_report.licenses.select do |license|
          licenses.include?(normalize_license_name(license.name)) || licenses.include?(license.id)
        end
      end

      def license_types_unknown_expression_fallback_enabled?
        Feature.enabled?(:license_types_unknown_expression_fallback, project)
      end
      strong_memoize_attr :license_types_unknown_expression_fallback_enabled?

      def licenses_with_dependencies(comparison_report, licenses)
        result = licenses_matching_name_or_id(comparison_report, licenses).each_with_object({}) do |license, memo|
          name = normalize_license_name(license.name)
          (memo[name] ||= []).concat(license.dependencies.map(&:name))
        end
        result.transform_values(&:uniq)
      end

      # Licenses from policies may match either spdx or name.
      # If we find either in the report, we take also the other value into comparison
      def extend_from_report(comparison_report, software_license_policies)
        licenses = join_ids_and_names(
          software_license_policies.filter_map(&:spdx_identifier),
          software_license_policies.filter_map(&:name)
        )

        licenses += licenses_matching_name_or_id(comparison_report, licenses).flat_map do |license|
          [license.id, normalize_license_name(license.name)]
        end
        licenses.compact.uniq
      end

      def new_dependencies_with_denied_licenses(denied_licenses)
        licenses_with_dependencies(report, denied_licenses)
          .transform_values { |dependency_names| dependency_names & newly_introduced_dependency_names }
          .select { |_license, dependency_names| dependency_names.present? }
      end

      def newly_introduced_dependency_names
        report.dependency_names - target_branch_report.dependency_names
      end
    end
  end
end
