# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class PolicyViolationComment
      include Rails.application.routes.url_helpers
      include Gitlab::Utils::StrongMemoize
      include Security::ScanResultPolicies::HumanizationHelpers

      MESSAGE_HEADER = '<!-- policy_violation_comment -->'
      VIOLATED_REPORTS_HEADER_PATTERN = /<!-- violated_reports: ([a-z_,]+)/
      OPTIONAL_APPROVALS_HEADER_PATTERN = /<!-- optional_approvals: ([a-z_,]+)/
      REPORT_TYPES = {
        license_scanning: 'license_scanning',
        scan_finding: 'scan_finding',
        any_merge_request: 'any_merge_request'
      }.freeze

      MORE_VIOLATIONS_DETECTED = 'More violations have been detected in addition to the list above.'
      VIOLATIONS_BLOCKING_TITLE = ':warning: **Violations blocking this merge request**'
      VIOLATIONS_DETECTED_TITLE = ':warning: **Violations detected in this merge request**'
      VIOLATIONS_BYPASSABLE_TITLE = ':construction: **Violations from warn mode policies that users can bypass**'

      attr_reader :reports, :optional_approval_reports, :existing_comment, :merge_request

      def initialize(existing_comment, merge_request, enabled_violated_policy_ids: nil)
        @existing_comment = existing_comment
        @reports = Set.new
        @optional_approval_reports = Set.new
        @merge_request = merge_request
        @enabled_violated_policy_ids = enabled_violated_policy_ids

        return unless existing_comment

        parse_reports
      end

      def add_report_type(report_type, requires_approval)
        add_optional_approval_report(report_type) unless requires_approval
        @reports = (reports + [report_type]) & REPORT_TYPES.values
      end

      def add_optional_approval_report(report_type)
        @optional_approval_reports = (optional_approval_reports + [report_type]) & REPORT_TYPES.values
      end

      def remove_report_type(report_type)
        @optional_approval_reports -= [report_type]
        @reports -= [report_type]
      end

      def clear_report_types
        @optional_approval_reports.clear
        @reports.clear
      end

      def body
        return if existing_comment.nil? && reports.empty?

        [MESSAGE_HEADER, body_message].join("\n")
      end
      strong_memoize_attr :body

      private

      delegate :project, to: :merge_request

      def parse_reports
        parse_report_list(VIOLATED_REPORTS_HEADER_PATTERN) { |report_type| add_report_type(report_type, true) }
        parse_report_list(OPTIONAL_APPROVALS_HEADER_PATTERN) { |report_type| add_optional_approval_report(report_type) }
      end

      def parse_report_list(pattern, &block)
        match = existing_comment.note.match(pattern)
        match[1].split(',').each(&block) if match
      end

      def fixed_note_body
        'Security policy violations have been resolved.'
      end

      def reports_header
        optional_approvals_sorted_list = optional_approval_reports.sort.join(',')

        <<~MARKDOWN
        <!-- violated_reports: #{reports.sort.join(',')} -->
        #{"<!-- optional_approvals: #{optional_approvals_sorted_list} -->" if optional_approval_reports.any?}
        MARKDOWN
      end

      def body_message
        return fixed_note_body if reports.empty?

        [
          summary,
          violations_overview,
          error_messages,
          comparison_pipelines,
          warn_mode_approval_setting_conflicts
        ].compact.join("\n")
      end

      def blocking_violations?
        reports != optional_approval_reports && details.fail_closed_policies.present?
      end

      def details
        ::Security::ScanResultPolicies::PolicyViolationDetails.new(
          merge_request,
          enabled_violated_policy_ids: @enabled_violated_policy_ids
        )
      end
      strong_memoize_attr :details

      def summary
        <<~MARKDOWN
        #{reports_header}
        #{merge_request.author.name}, this merge request has policy violations and errors.
        #{blocking_violations? ? "**To unblock this merge request, fix these items:**\n" : ''}
        #{violation_summary}
        #{
          if blocking_violations?
            "If you think these items shouldn't be violations, ask eligible approvers of each policy to approve this merge request."
          else
            'Consider including optional reviewers based on the policy rules in the MR widget.'
          end
        }
        #{warn_mode_summary}
        #{
          if details.fail_open_policies.any?
            "\nThe following policies enforced on your project were skipped because they are configured to fail open: " \
              "#{details.fail_open_policies.join(', ')}.\n\n#{array_to_list(details.fail_open_messages)}"
          end
        }
        MARKDOWN
      end

      def violation_summary
        fail_closed_policies = details.fail_closed_policies
        return if fail_closed_policies.blank?

        any_merge_request_policies = details.fail_closed_policies(:any_merge_request)
        license_scanning_policies = details.fail_closed_policies(:license_scanning)
        errors = details.errors
        summary = ["Resolve all violations in the following merge request approval policies: " \
          "#{fail_closed_policies.join(', ')}."]

        if any_merge_request_policies.present?
          summary << "Acquire approvals from eligible approvers defined in the following " \
            "merge request approval policies: #{any_merge_request_policies.join(', ')}."
        end

        if license_scanning_policies.present? && enforced_license_scanning_violations_list.present?
          summary << ("Remove all denied licenses identified by the following merge request approval policies: " \
            "#{license_scanning_policies.join(', ')}")
        end

        summary << 'Resolve the errors and re-run the pipeline.' if errors.present?

        array_to_list(summary)
      end

      def violations_overview
        <<~MARKDOWN
        #{enforced_violations_overview}
        #{warn_mode_violations_overview}
        MARKDOWN
      end
      strong_memoize_attr :violations_overview

      def enforced_violations_overview
        return if details.enforced_violations.empty?

        <<~MARKDOWN
        ### #{VIOLATIONS_BLOCKING_TITLE}
        #{enforced_scan_finding_violations}
        #{enforced_any_merge_request_violations}
        #{enforced_license_finding_violations}
        ---
        MARKDOWN
      end

      def enforced_scan_finding_violations
        if details.new_enforced_scan_finding_violations.empty? &&
            details.previous_enforced_scan_finding_violations.empty?
          return
        end

        <<~MARKDOWN
        #{new_enforced_scan_finding_violations}
        #{previous_enforced_scan_finding_violations}
        MARKDOWN
      end

      def enforced_any_merge_request_violations
        violations = details.enforced_any_merge_request_violations

        return if violations.empty?

        <<~MARKDOWN
        #### Enforced `any_merge_request` violations
        #{any_merge_request_overview(violations)}
        #{any_merge_request_commits(violations)}
        MARKDOWN
      end

      def warn_mode_any_merge_request_violations
        violations = details.warn_mode_any_merge_request_violations

        return if violations.empty?

        <<~MARKDOWN
        #### `any_merge_request` violations that users can bypass
        #{any_merge_request_overview(violations, bypassable: true)}
        #{any_merge_request_commits(violations)}
        MARKDOWN
      end

      def new_enforced_scan_finding_violations
        violations = details.new_enforced_scan_finding_violations

        return if violations.empty?

        <<~MARKDOWN
        #### Newly detected enforced `scan_finding` violations
        #{scan_finding_violations(violations)}
        MARKDOWN
      end

      def previous_enforced_scan_finding_violations
        violations = details.previous_enforced_scan_finding_violations

        return if violations.empty?

        <<~MARKDOWN
        #### Previously existing enforced `scan_finding` violations
        #{scan_finding_violations(violations)}
        MARKDOWN
      end

      def enforced_license_finding_violations
        return if details.enforced_license_scanning_violations.empty?

        <<~MARKDOWN
        #### Enforced `license_finding` violations

        Out-of-policy licenses:

        #{violations_list(enforced_license_scanning_violations_list)}
        MARKDOWN
      end

      def warn_mode_violations_overview
        return if details.warn_mode_violations.empty?

        <<~MARKDOWN
        ### #{VIOLATIONS_BYPASSABLE_TITLE}
        #{warn_mode_scan_finding_violations}
        #{warn_mode_any_merge_request_violations}
        #{warn_mode_license_finding_violations}
        ---
        MARKDOWN
      end

      def warn_mode_scan_finding_violations
        if details.new_warn_mode_scan_finding_violations.empty? &&
            details.previous_warn_mode_scan_finding_violations.empty?
          return
        end

        <<~MARKDOWN
        #{new_warn_mode_scan_finding_violations}
        #{previous_warn_mode_scan_finding_violations}
        MARKDOWN
      end

      def new_warn_mode_scan_finding_violations
        violations = details.new_warn_mode_scan_finding_violations

        return if violations.empty?

        <<~MARKDOWN
        #### Newly detected `scan_finding` violations that users can bypass
        #{scan_finding_violations(violations)}
        MARKDOWN
      end

      def previous_warn_mode_scan_finding_violations
        violations = details.previous_warn_mode_scan_finding_violations

        return if violations.empty?

        <<~MARKDOWN
        #### Previously found `scan_finding` violations that users can bypass
        #{scan_finding_violations(violations)}
        MARKDOWN
      end

      def warn_mode_license_finding_violations
        return if details.warn_mode_license_scanning_violations.empty?

        <<~MARKDOWN
        #### `license_finding` violations that users can bypass

        Out-of-policy licenses:

        #{violations_list(warn_mode_license_scanning_violations_list)}
        MARKDOWN
      end

      def newly_introduced_violations
        scan_finding_violations(
          details.new_scan_finding_violations, 'This merge request introduces the following violations')
      end
      strong_memoize_attr :newly_introduced_violations

      def previously_existing_violations
        scan_finding_violations(details.previous_scan_finding_violations, 'Previously existing vulnerabilities')
      end
      strong_memoize_attr :previously_existing_violations

      def scan_finding_violations(violations)
        list = violations.map do |violation|
          build_scan_finding_violation_line(violation)
        end
        return if list.empty?

        <<~MARKDOWN
        #{violations_list(list)}
        MARKDOWN
      end

      def license_scanning_violations
        return if license_scanning_violations_list.empty?

        <<~MARKDOWN
        :warning: **Out-of-policy licenses:**

        #{violations_list(license_scanning_violations_list)}
        MARKDOWN
      end

      def enforced_license_scanning_violations_list
        details.enforced_license_scanning_violations.map do |violation|
          build_license_scanning_violation_line(violation)
        end
      end

      def warn_mode_license_scanning_violations_list
        details.warn_mode_license_scanning_violations.map do |violation|
          build_license_scanning_violation_line(violation)
        end
      end

      def build_license_scanning_violation_line(violation)
        dependencies = violation.dependencies
        "1. #{violation.url.present? ? "[#{violation.license}](#{violation.url})" : violation.license}: " \
          "Used by #{dependencies.first(Security::ScanResultPolicyViolation::MAX_VIOLATIONS).join(', ')}" \
          "#{dependencies.size > Security::ScanResultPolicyViolation::MAX_VIOLATIONS ? ', …and more' : ''}"
      end

      def build_scan_finding_violation_line(violation)
        line = "1."
        line += " #{violation.severity.capitalize} **·**" if violation.severity
        line += " #{violation.name}" if violation.name

        if violation.identifier.present?
          line += " **·** [#{violation.identifier[:name]}](#{violation.identifier[:url]})"
        end

        if violation.path.present?
          location = violation.location
          location_description = ''
          start_line = location[:start_line]
          location_description += "Line #{start_line} " if start_line.present?
          package_name = location.dig(:dependency, :package, :name)
          package_version = location.dig(:dependency, :version)
          location_description += "Package #{package_name} " if package_name.present?
          location_description += "(#{package_version}) " if package_version.present?
          location_description += 'in ' if location_description.present?
          line += " **·** [#{location_description}#{location[:file]}](#{violation.path})"
        end

        line += " (#{violation.report_type.humanize})" if violation.report_type

        enrichment_info = build_enrichment_info(violation)
        line += "\n  #{enrichment_info}" if enrichment_info.present?

        line
      end

      def build_enrichment_info(violation)
        enrichments = violation.cve_enrichments
        return if enrichments.blank?

        enrichments.map do |enrichment|
          epss = enrichment.epss_score || HumanizationHelpers::UNKNOWN

          known_exploited = humanized_boolean(enrichment.is_known_exploit)

          " - `#{enrichment.cve}` **·** EPSS: #{epss} **·** Known Exploited: #{known_exploited}"
        end.join("\n  ")
      end

      def any_merge_request_overview(violations, bypassable: false)
        list = violations.sort_by(&:name).map do |violation|
          description = case violation.commits
                        when Array then s_("ScanResultPolicy|any unsigned commits")
                        when true then s_("ScanResultPolicy|any commits")
                        else next
                        end

          "* #{violation.name}: #{description}"
        end

        description = case bypassable
                      when true then "The following policies require either approval or bypass"
                      else "The following policies require approval"
                      end

        <<~MARKDOWN
        #{description}:

        #{list.join("\n")}
        MARKDOWN
      end

      def any_merge_request_commits(violations)
        list = violations.flat_map do |violation|
          next unless violation.commits.is_a?(Array)

          violation.commits.map do |commit|
            "1. [`#{Commit.truncate_sha(commit)}`](#{unsigned_commit_url(commit)})"
          end
        end.compact
        return if list.empty?

        <<~MARKDOWN
          Unsigned commits:

          #{violations_list(list)}
        MARKDOWN
      end

      # Violations synced before full SHAs were stored hold short SHAs, which the MR diff view cannot resolve.
      def unsigned_commit_url(sha)
        return project_commit_url(project, sha) unless Gitlab::Git.commit_id?(sha)

        diffs_project_merge_request_url(project, merge_request, commit_id: sha)
      end

      def violations_list(list)
        [
          list.first(Security::ScanResultPolicyViolation::MAX_VIOLATIONS).join("\n"),
          list.size > Security::ScanResultPolicyViolation::MAX_VIOLATIONS ? "\n#{MORE_VIOLATIONS_DETECTED}" : nil
        ].compact.join("\n")
      end

      def error_messages
        errors = details.errors
        return if errors.blank?

        <<~MARKDOWN
        :exclamation: **Errors**

        #{errors.map { |error| "- #{error.message}" }.join("\n")}
        MARKDOWN
      end

      def warn_mode_approval_setting_conflicts
        return unless details.warn_mode_policies.any?

        overrides = ::Security::ScanResultPolicies::ApprovalSettingsOverrides.new(
          project: merge_request.target_project,
          warn_mode_policies: details.warn_mode_policies,
          enforced_policies: details.enforced_security_policies
        ).all

        return if overrides.empty?

        <<~MARKDOWN
        :lock: **Warn mode policies set more restrictive approval settings**

        Some security policies have `approval_settings` that are more restrictive than this
        project's merge request approval settings, taking into account the `approval_settings`
        of enforced policies. When the following warn mode policies are strictly enforced,
        their approval settings take precedence:

        #{overrides.map { |override| warn_mode_approval_settings_overrides(override) }.join("\n")}
        MARKDOWN
      end

      def warn_mode_approval_settings_overrides(override)
        policy_names = override
                         .security_policies
                         .pluck(:name) # rubocop:disable CodeReuse/ActiveRecord -- false positive: `Enumerable#pluck`
                         .sort
                         .map { |name| "`#{name}`" }
                         .join(", ")

        "* __#{humanized_approval_setting(override.attribute)}__: #{policy_names}"
      end

      def comparison_pipelines
        pipelines = details.comparison_pipelines
        return if pipelines.blank?

        render_title = pipelines.many? # rubocop:disable CodeReuse/ActiveRecord -- pipelines is an array
        <<~MARKDOWN
        :information_source: **Comparison pipelines**

        #{pipelines.map { |pipeline| build_comparison_pipelines_info(pipeline, render_title) }.join("\n")}
        MARKDOWN
      end

      def build_comparison_pipelines_info(pipeline, render_title)
        pipeline_to_link = ->(id) { "[##{id}](#{project_pipeline_url(project, id)})" }
        source_pipeline_links = pipeline.source.map(&pipeline_to_link)
        target_pipeline_links = pipeline.target.map(&pipeline_to_link)

        info = <<~MARKDOWN
        - Target branch (`#{merge_request.target_branch}`): #{target_pipeline_links.join(', ').presence || 'None'}
        - Source branch (`#{merge_request.source_branch}`): #{source_pipeline_links.join(', ').presence || 'None'}
        MARKDOWN

        [(pipeline.report_type.humanize if render_title), info].compact.join("\n")
      end

      def warn_mode_summary
        return unless details.warn_mode_policies.any?

        warn_mode_policy_names = details.warn_mode_policies.map(&:name).sort

        "\n**Note:** The following policies are in warn mode and can be bypassed to make approvals optional: \n" \
          "#{array_to_list(warn_mode_policy_names)}"
      end

      def array_to_list(array)
        array.map { |item| "- #{item}" }.join("\n")
      end
    end
  end
end
