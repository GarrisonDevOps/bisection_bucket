# frozen_string_literal: true

module Security
  module MergeRequestApprovalPolicies
    class DeniedLicensesChecker
      include Gitlab::Utils::StrongMemoize
      include Gitlab::InternalEventsTracking
      include Security::LicenseOverrides::Shared

      def initialize(project, report, target_branch_report, approval_policy_source)
        @project = project
        @report = report
        @target_branch_report = target_branch_report
        @approval_policy_source = approval_policy_source
      end

      def denied_licenses_with_dependencies
        licenses_violating_policy = []
        policy_denied_licenses = policy_licenses["denied"]
        policy_allowed_licenses = policy_licenses["allowed"]

        if policy_denied_licenses
          track_package_exception_event('denylist')
          licenses_violating_policy = check_denied_licenses(policy_denied_licenses)
        elsif policy_allowed_licenses
          track_package_exception_event('allowlist')
          licenses_violating_policy = check_allowed_licenses(policy_allowed_licenses)
        end

        return unless licenses_violating_policy.present?

        license_dependencies_map(licenses_violating_policy)
      end

      private

      attr_reader :project, :report, :target_branch_report, :approval_policy_source

      def policy_licenses
        approval_policy_source&.licenses || {}
      end
      strong_memoize_attr :policy_licenses

      def license_dependencies_map(licenses_violating_policy)
        licenses_violating_policy_map = Hash.new(Set.new)

        licenses_violating_policy.each do |license|
          licenses_violating_policy_map[license.name] += license.dependencies.map(&:name)
        end

        licenses_violating_policy_map.deep_transform_values(&:to_a)
      end

      def check_allowed_licenses(policy_allowed_licenses)
        policy_allowed_license_names = policy_allowed_licenses.pluck("name") # rubocop: disable CodeReuse/ActiveRecord -- Not an ActiveRecord
        licenses_to_check_names = licenses_to_check.map(&:name)
        denied_licenses_in_report_names = licenses_to_check_names - policy_allowed_license_names

        # these are violations, we don't need to check the packages
        denied_licenses_in_report = licenses_to_check.select do |license|
          denied_licenses_in_report_names.include?(license.name)
        end

        # for the allowed licenses in the report we need to check the package exceptions
        allowed_licenses_in_report = licenses_to_check_names & policy_allowed_license_names

        return denied_licenses_in_report if allowed_licenses_in_report.blank?

        allowed_licenses_with_excluded_packages = check_packages_exceptions(allowed_licenses_in_report,
          policy_allowed_licenses)

        denied_licenses_in_report + allowed_licenses_with_excluded_packages
      end

      def check_packages_exceptions(allowed_licenses_in_report, policy_allowed_licenses)
        allowed_licenses_with_excluded_packages = []

        policy_allowed_licenses_map = policy_allowed_licenses.index_by { |license| license["name"] }

        allowed_licenses_in_report.each do |allowed_license_name|
          policy_allowed_license = policy_allowed_licenses_map[allowed_license_name]
          next unless policy_allowed_license.present?

          excluded_packages_for_license = excluded_packages_for_license(policy_allowed_license)
          next unless excluded_packages_for_license.present?

          # the same license can appear in both reports with different dependencies
          report_allowed_licenses = report_allowed_license_map[allowed_license_name]
          next unless report_allowed_licenses.present?

          report_allowed_licenses.each do |report_allowed_license|
            not_allowed_packages = excluded_packages_for_allowed_license(report_allowed_license,
              excluded_packages_for_license)

            allowed_licenses_with_excluded_packages << report_allowed_license if not_allowed_packages.present?
          end
        end
        allowed_licenses_with_excluded_packages
      end

      def report_allowed_license_map
        licenses_to_check.each_with_object(Hash.new { |h, k| h[k] = [] }) do |license, map|
          map[license.name] << license
        end
      end
      strong_memoize_attr :report_allowed_license_map

      def excluded_packages_for_license(license)
        license.dig("packages", "excluding", "purls")
      end

      def excluded_packages_for_allowed_license(allowed_license, packages_excluded)
        dependencies_purl = allowed_license.dependencies.map(&:purl)

        dependencies_purl.select do |dep|
          packages_excluded.any? { |pkg| dep.start_with?(pkg) }
        end
      end

      def check_denied_licenses(policy_denied_licenses)
        licenses_violating_policy = []
        denied_licenses_in_report = denied_licenses_found_in_report(policy_denied_licenses)

        denied_licenses_in_report.each do |denied_license_name|
          denied_license_policy = policy_denied_licenses.find { |denied| denied["name"] == denied_license_name }
          packages_excluded = denied_license_policy.dig("packages", "excluding", "purls")

          # The same license can appears multiple times with different dependencies
          denied_licenses = licenses_to_check.find_all { |license| license.name == denied_license_name }

          next licenses_violating_policy.push(*denied_licenses) unless packages_excluded.present?

          denied_licenses_with_not_allowed_packages = denied_licenses_with_not_allowed_packages(denied_licenses,
            packages_excluded)

          # if all components of the given license are in the excluding list it is not a violation
          next if denied_licenses_with_not_allowed_packages.blank?

          licenses_violating_policy.push(*denied_licenses_with_not_allowed_packages)
        end

        licenses_violating_policy
      end

      def denied_licenses_found_in_report(policy_denied_licenses)
        policy_denied_license_names = policy_denied_licenses.pluck("name") # rubocop: disable CodeReuse/ActiveRecord -- Not an ActiveRecord
        licenses_to_check_names = licenses_to_check.map(&:name)
        licenses_to_check_names & policy_denied_license_names
      end

      def denied_licenses_with_not_allowed_packages(denied_licenses, packages_excluded)
        denied_licenses_with_not_allowed_packages = []

        denied_licenses.each do |denied_license|
          dependencies_purl = denied_license.dependencies.map(&:purl)

          not_allowed_packages = dependencies_purl.reject do |dep|
            packages_excluded.any? { |pkg| dep.starts_with?(pkg) }
          end

          denied_licenses_with_not_allowed_packages.push(denied_license) if not_allowed_packages.present?
        end

        denied_licenses_with_not_allowed_packages
      end

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

      def track_package_exception_event(licenses_list_type)
        track_internal_event(
          'enforce_approval_policies_with_package_exceptions_in_project',
          project: project,
          additional_properties: {
            label: licenses_list_type
          }
        )
      end
    end
  end
end
