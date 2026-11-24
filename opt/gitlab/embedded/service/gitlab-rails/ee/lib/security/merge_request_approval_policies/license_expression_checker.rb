# frozen_string_literal: true

module Security
  module MergeRequestApprovalPolicies
    # Evaluates license policy violations for reports that may contain SPDX
    # compound expressions (e.g. "MIT AND Apache-2.0") rather than plain license names.
    #
    # Supports both denylist and allowlist policies, AND, OR, WITH, and PLUS expressions,
    # single-identifier licenses, and LicenseRef/DocumentRef matching rules (including
    # LicenseRef wildcard).
    class LicenseExpressionChecker
      include Gitlab::InternalEventsTracking
      include Security::LicenseOverrides::Shared
      include Gitlab::SPDX::ExpressionEvaluator
      include Gitlab::SPDX::ExpressionParsing

      LICENSE_REF_PREFIX = 'LicenseRef-'
      DOCUMENT_REF_PREFIX = 'DocumentRef-'
      LICENSE_REF_WILDCARD = 'LicenseRef-*'
      LICENSE_REF_PREFIX_DOWNCASE = LICENSE_REF_PREFIX.downcase.freeze
      DOCUMENT_REF_PREFIX_DOWNCASE = DOCUMENT_REF_PREFIX.downcase.freeze
      SPDX_VERSION_SUFFIX_PATTERN = /(?<version>\d+(?:\.\d+)+)\z/
      PLUS_SUFFIX_PATTERN = /\A(?<base>.+)\+\z/

      # Pre-computes value-derived data once per license value so that
      # downcased and resolved_id are not recomputed on every denied-name iteration.
      ValueMatchInfo = Data.define(:value, :downcased, :resolved_id) do
        def license_ref?
          downcased.start_with?(LICENSE_REF_PREFIX_DOWNCASE)
        end

        def document_ref?
          downcased.start_with?(DOCUMENT_REF_PREFIX_DOWNCASE)
        end
      end

      def initialize(project, report, target_branch_report, approval_policy_source)
        @project = project
        @report = report
        @target_branch_report = target_branch_report
        @approval_policy_source = approval_policy_source
      end

      def denied_licenses_with_dependencies
        policy_denied_licenses = policy_licenses["denied"]
        policy_allowed_licenses = policy_licenses["allowed"]

        licenses_violating_policy =
          if policy_allowed_licenses.present?
            track_policy_enforcement_events('allowlist')
            check_allowed_licenses(policy_allowed_licenses)
          elsif policy_denied_licenses.present?
            track_policy_enforcement_events('denylist')
            check_denied_licenses(policy_denied_licenses)
          end

        return unless licenses_violating_policy.present?

        license_dependencies_map(licenses_violating_policy)
      end

      private

      attr_reader :project, :report, :target_branch_report, :approval_policy_source

      def policy_licenses
        approval_policy_source&.licenses || {}
      end

      def license_dependencies_map(licenses_violating_policy)
        licenses_violating_policy_map = Hash.new { |h, k| h[k] = Set.new }

        licenses_violating_policy.each do |license|
          licenses_violating_policy_map[license.name] += license.dependencies.map(&:name)
        end

        licenses_violating_policy_map.deep_transform_values(&:to_a)
      end

      def check_allowed_licenses(policy_allowed_licenses)
        allowed_names = policy_allowed_licenses.pluck("name") # rubocop: disable CodeReuse/ActiveRecord -- Not an ActiveRecord
        exceptions_map = package_exceptions_map(policy_allowed_licenses)

        licenses_to_check.select { |license| violates_allowlist?(license, allowed_names, exceptions_map) }
      end

      def check_denied_licenses(policy_denied_licenses)
        denied_names = policy_denied_licenses.pluck("name") # rubocop: disable CodeReuse/ActiveRecord -- Not an ActiveRecord
        exceptions_map = package_exceptions_map(policy_denied_licenses)

        licenses_to_check.select { |license| violates_denylist?(license, denied_names, exceptions_map) }
      end

      def violates_allowlist?(license, allowed_names, exceptions_map)
        node = parse_expression(license.name).node

        return true unless evaluate(node, allowed_names)
        return false if exceptions_map.empty?

        license.dependencies.any? do |dependency|
          !evaluate(node, applicable_license_names(allowed_names, dependency, exceptions_map))
        end
      end

      def violates_denylist?(license, denied_names, exceptions_map)
        node = parse_expression(license.name).node

        return evaluate_violation(node, denied_names) if exceptions_map.empty?

        license.dependencies.any? do |dependency|
          evaluate_violation(node, applicable_license_names(denied_names, dependency, exceptions_map))
        end
      end

      def package_exceptions_map(policy_licenses)
        policy_licenses.each_with_object({}) do |license, map|
          purls = excluded_packages_for_license(license)
          map[license["name"]] = purls if purls.present?
        end
      end

      def excluded_packages_for_license(license)
        license.dig("packages", "excluding", "purls")
      end

      def applicable_license_names(license_names, dependency, exceptions_map)
        return license_names if dependency.purl.blank?

        license_names.reject do |license_name|
          dependency_excepted_for_license?(dependency, license_name, exceptions_map)
        end
      end

      def dependency_excepted_for_license?(dependency, license_name, exceptions_map)
        purls = exceptions_map[license_name]
        purls.present? && purl_excepted?(dependency, purls)
      end

      def purl_excepted?(dependency, excluding_purls)
        purl = dependency.purl
        return false if purl.blank?

        excluding_purls.any? { |excluded_purl| purl.start_with?(excluded_purl) }
      end

      # Node matching, walked by Gitlab::SPDX::ExpressionEvaluator#evaluate (allow-list,
      # `context` is the allowed names) and #evaluate_violation (deny-list, `context` is
      # the denied names). These hooks don't encode allow/deny meaning; only the AND/OR
      # combinator dispatch in the shared mixin does.
      def evaluate_id(node, allowed_names)
        return true if evaluate_leaf(node.value, allowed_names)

        report_base_info = value_match_info(node.value)
        allowed_names.any? do |policy_name|
          next false unless policy_name.end_with?('+')

          policy_plus_covers_report_base?(policy_name, node.value, report_base_info)
        end
      end

      def evaluate_literal(node, allowed_names)
        allowed_names.include?(node.value)
      end

      def evaluate_plus(node, allowed_names)
        if license_ref_identifier?(node.value) || document_ref_identifier?(node.value)
          return allowed_names.any? { |policy_name| matches_policy_name?(value_match_info(node.value), policy_name) }
        end

        report_base = node.value.delete_suffix('+')
        report_base_info = value_match_info(report_base)
        allowed_names.any? { |policy_name| policy_plus_covers_report_base?(policy_name, report_base, report_base_info) }
      end

      def evaluate_fallback(node, allowed_names)
        allowed_names.include?(node.value.to_s)
      end

      def evaluate_leaf(value, allowed_names)
        info = value_match_info(value)
        allowed_names.any? { |policy_name| matches_policy_name?(info, policy_name) }
      end

      # Checks whether a policy name covers a given report base identifier.
      # `policy_name` may or may not carry a `+` suffix depending on the call site:
      # - From `evaluate_id`: always `+`-suffixed (enforced by the caller's guard),
      #   so the first two early returns below are no-ops there.
      # - From `evaluate_plus`: may be plain or `+`-suffixed.
      def policy_plus_covers_report_base?(policy_name, report_base, report_base_info)
        return false if license_ref_identifier?(policy_name) || document_ref_identifier?(policy_name)
        return true if policy_name == report_base
        return true if matches_policy_name?(report_base_info, policy_name)

        policy_match = policy_name.match(PLUS_SUFFIX_PATTERN)
        return false unless policy_match

        policy_base = policy_match[:base]

        return true if spdx_version(policy_base).nil? && policy_base == report_base

        spdx_version_gte?(report_base, policy_base)
      end

      def spdx_version_gte?(report_base, policy_base)
        report_version = spdx_version(report_base)
        policy_version = spdx_version(policy_base)
        return false unless report_version && policy_version

        report_prefix = report_base.delete_suffix("-#{report_version}")
        policy_prefix = policy_base.delete_suffix("-#{policy_version}")
        return false unless report_prefix == policy_prefix

        report_parts = report_version.split('.').map(&:to_i)
        policy_parts = policy_version.split('.').map(&:to_i)
        length = [report_parts.length, policy_parts.length].max

        report_parts.fill(0, report_parts.length...length)
        policy_parts.fill(0, policy_parts.length...length)

        (report_parts <=> policy_parts) >= 0
      end

      def spdx_version(value)
        value.match(SPDX_VERSION_SUFFIX_PATTERN)&.[](:version)
      end

      def value_match_info(value)
        ValueMatchInfo.new(
          value: value,
          downcased: value.to_s.downcase,
          resolved_id: resolve_id(value)
        )
      end

      def matches_policy_name?(info, policy_name)
        if policy_name.casecmp(LICENSE_REF_WILDCARD) == 0
          info.license_ref?
        elsif case_insensitive_identifier_match?(policy_name, info)
          true
        else
          info.resolved_id == policy_name
        end
      end

      def case_insensitive_identifier_match?(policy_name, info)
        info.value.casecmp(policy_name) == 0 &&
          ((license_ref_identifier?(policy_name) && info.license_ref?) ||
            (document_ref_identifier?(policy_name) && info.document_ref?))
      end

      def license_ref_identifier?(value)
        value.to_s.downcase.start_with?(LICENSE_REF_PREFIX_DOWNCASE)
      end

      def document_ref_identifier?(value)
        value.to_s.downcase.start_with?(DOCUMENT_REF_PREFIX_DOWNCASE)
      end

      # Policies store display names (e.g. "MIT License") but SPDX expressions contain IDs
      # (e.g. "MIT"). Unknown identifiers are kept as-is.
      def resolve_id(id)
        spdx_catalogue_map[id] || id
      end

      def spdx_catalogue_map
        Gitlab::SPDX::Catalogue.latest_active_licenses.to_h { |l| [l.id, l.name] }
      end
      strong_memoize_attr :spdx_catalogue_map

      def licenses_to_check
        base_licenses = if only_newly_detected?
                          diff = target_branch_report
                            .diff_with_including_new_dependencies_for_unchanged_licenses(report)
                          diff[:added]
                        elsif include_newly_detected?
                          report.licenses + target_branch_report.licenses
                        else
                          target_branch_report.licenses
                        end

        apply_license_overrides(base_licenses)
      end
      strong_memoize_attr :licenses_to_check

      # Defense-in-depth: applies license overrides at the approval evaluation layer.
      # The primary override injection happens upstream in SbomScanner#report, which feeds
      # both the MR security widget and this checker. This secondary application ensures
      # overrides are enforced even if the SbomScanner path is bypassed or the report
      # is constructed from a different source.
      # Can be removed entirely (along with active_overrides, find_override_for,
      # rebuild_license, build_override_license, and build_license_with_deps) once
      # SbomScanner injection is confirmed as the stable canonical path.
      def apply_license_overrides(licenses)
        overrides = active_overrides
        return licenses if overrides.blank?

        overridden_deps = Hash.new { |h, k| h[k] = [] }
        result_licenses = []

        licenses.each do |license|
          remaining_deps = []

          license.dependencies.each do |dep|
            override = find_override_for(dep, license, overrides)

            if override
              overridden_deps[override['license']] << dep
            else
              remaining_deps << dep
            end
          end

          next if remaining_deps.empty?

          result_licenses << rebuild_license(license, remaining_deps)
        end

        overridden_deps.each do |license_name, deps|
          result_licenses << build_override_license(license_name, deps)
        end

        result_licenses
      end

      def active_overrides
        return [] unless ::Security::LicenseOverrideApplicator.experiment_enabled_for_project?(project)

        approval_policy_source&.resolved_approval_policy_rule&.license_overrides || []
      end
      strong_memoize_attr :active_overrides

      def find_override_for(dependency, license, overrides)
        return unless dependency.purl.present?

        overrides.find do |override|
          purl_matches = purl_matches?(dependency.purl, override['purl'])
          mode = override.fetch('mode', MODES[:patch])
          mode_applies = mode == MODES[:overwrite] || license.id.blank? || license.name == 'unknown'

          purl_matches && mode_applies
        end
      end

      def rebuild_license(original, deps)
        build_license_with_deps(id: original.id, name: original.name, url: original.url, deps: deps)
      end

      def build_override_license(name, deps)
        spdx_id, resolved_name, url = resolve_license_identity(name)
        build_license_with_deps(id: spdx_id, name: resolved_name, url: url || '', deps: deps)
      end

      def build_license_with_deps(id:, name:, url:, deps:)
        new_license = Gitlab::Ci::Reports::LicenseScanning::License.new(id: id, name: name, url: url)

        deps.each do |dep|
          new_license.add_dependency(
            name: dep.name, purl_type: dep.purl_type, version: dep.version,
            package_manager: dep.package_manager, path: dep.path
          )
        end

        new_license
      end

      def only_newly_detected?
        license_states == [ApprovalProjectRule::NEWLY_DETECTED]
      end

      def include_newly_detected?
        license_states.include?(ApprovalProjectRule::NEWLY_DETECTED)
      end

      def license_states
        approval_policy_source&.license_states || []
      end
      strong_memoize_attr :license_states

      def track_policy_enforcement_events(licenses_list_type)
        Gitlab::InternalEvents.with_batched_redis_writes do
          track_internal_event(
            'enforce_approval_policies_with_package_exceptions_in_project',
            project: project,
            additional_properties: {
              label: licenses_list_type
            }
          )

          next unless report_contains_license_expression?

          track_internal_event(
            'enforce_approval_policies_with_license_expressions_in_project',
            project: project,
            additional_properties: {
              label: licenses_list_type
            }
          )
        end
      end

      def report_contains_license_expression?
        licenses_to_check.any? { |license| license_expression?(license.name) }
      end

      def license_expression?(name)
        node = parse_expression(name).node

        ::Gitlab::SPDX::ExpressionEvaluator::COMPOUND_NODE_TYPES.include?(node.type) ||
          license_ref_identifier?(name) ||
          document_ref_identifier?(name)
      end
    end
  end
end
