# frozen_string_literal: true

module Security
  module DependencyFirewall
    class EnforcementService
      private_class_method :new

      PACKAGE_DOWNLOAD  = 1
      PACKAGE_UPLOAD    = 2
      CONTAINER_PULL    = 3
      CONTAINER_PUSH    = 4
      PACKAGE_FORWARDED = 5

      OPERATIONS = [
        PACKAGE_DOWNLOAD,
        PACKAGE_UPLOAD,
        CONTAINER_PULL,
        CONTAINER_PUSH,
        PACKAGE_FORWARDED
      ].freeze

      SUCCESS_ALLOWED = :allowed
      SUCCESS_BLOCKED = :blocked
      SUCCESS_WARNING = :warning

      # Allow reasons worth surfacing in the audit message; a plain evaluation/no-match allow is not.
      NOTABLE_ALLOWED_REASONS = %i[user_bypassed token_bypassed exception].freeze

      def self.firewall_check(project:, pkg_type:, name:, version:, operation:, current_user:, session_id: nil)
        new(
          project: project,
          pkg_type: pkg_type,
          name: name,
          version: version,
          operation: operation,
          current_user: current_user,
          session_id: session_id
        ).execute
      end

      def initialize(project:, pkg_type:, name:, version:, operation:, current_user:, session_id: nil)
        @project      = project
        @pkg_type     = pkg_type
        @name         = name
        @version      = version
        @operation    = operation
        @current_user = current_user
        # Sanitized here, at the choke point every caller passes through, rather than in one
        # caller: the keyword is public and neither recorder revalidates. Sanitizing is idempotent.
        @session_id   = ::Security::DependencyFirewall::SessionId.sanitize(session_id)
      end

      def execute
        # TODO: Project validation will be implemented in a future item: https://gitlab.com/gitlab-org/gitlab/-/work_items/591728
        raise ArgumentError, "DependencyFirewall: project is nil" if @project.nil?

        return response(SUCCESS_ALLOWED) unless Availability.enforced_for?(@project)

        raise ArgumentError, "DependencyFirewall: pkg_type is blank" if @pkg_type.blank?
        raise ArgumentError, "DependencyFirewall: name is blank" if @name.blank?

        unless OPERATIONS.include?(@operation)
          raise ArgumentError, "DependencyFirewall: operation #{@operation.inspect} is not valid"
        end

        start_time = Time.current
        enforce_policy(
          fetch_licenses.filter_map { |license| license[:name] },
          fetch_vulnerabilities,
          fetch_malicious,
          start_time
        )
      end

      private

      def fetch_licenses
        FetchPackageLicensesService.new(
          name: @name,
          purl_type: @pkg_type,
          version: @version
        ).execute
      end

      def fetch_vulnerabilities
        FetchPackageVulnerabilitiesService.new(
          name: @name,
          purl_type: @pkg_type,
          version: @version
        ).execute
      end

      def fetch_malicious
        FetchPackageMaliciousService.new(
          name: @name,
          purl_type: @pkg_type,
          version: @version
        ).execute
      end

      def enforce_policy(license_names, vulnerabilities, malicious_packages, start_time)
        results = Array(
          ::Security::DependencyFirewall::PolicyEvaluator
            .new(@project, @current_user)
            .evaluate(@name,
              purl_type: @pkg_type,
              version: @version,
              licenses: license_names,
              vulnerabilities: vulnerabilities,
              malicious_packages: malicious_packages)
        )

        audit_bypasses(results)

        denied = results.find { |r| r[:action] == ::Security::DependencyFirewallPolicies::Rule::ACTION_DENIED }
        if denied
          audit(:blocked, denied)
          track_event(SUCCESS_BLOCKED, start_time)
          record_activity(:blocked, denied)
          record_prevented_entities(results, vulnerabilities)
          return error_response(build_violation_message(denied), SUCCESS_BLOCKED)
        end

        warned = results.find { |r| r[:action] == ::Security::DependencyFirewallPolicies::Rule::ACTION_WARNED }
        if warned
          audit(:warned, warned)
          track_event(SUCCESS_WARNING, start_time)
          record_activity(:warned, warned)
          record_prevented_entities(results, vulnerabilities)
          return response(SUCCESS_WARNING, result: warned)
        end

        # "Allow" outcomes due to certain reasons like absence of rules/policy should not be reported in
        # the audit log to avoid noise
        return response(SUCCESS_ALLOWED) if nothing_evaluated?(results)

        allowed = notable_allowed_result(results)
        audit(:allowed, allowed)
        track_event(SUCCESS_ALLOWED, start_time)
        record_activity(:allowed, allowed)

        response(SUCCESS_ALLOWED)
      end

      # One ledger entry per denying rule, so each rule type's card counts it; never breaks enforcement.
      def record_prevented_entities(results, vulnerabilities)
        purl = build_purl
        return if purl.length > 512 # over-limit identifiers would poison the flush batch

        seen_at = Time.current

        results.each do |result|
          blocked = result[:action] == ::Security::DependencyFirewallPolicies::Rule::ACTION_DENIED
          warned = result[:action] == ::Security::DependencyFirewallPolicies::Rule::ACTION_WARNED
          next unless blocked || warned

          Array(result[:matched_rules]).each do |rule|
            # Types the ledger enum does not map yet (e.g. age) would raise in the buffer and skip later rules.
            rule_type = ::Security::DependencyFirewallPolicyRule.types[rule.type]
            next unless rule_type

            ::Security::DependencyFirewallPreventedPackage.write_buffer.add(
              project_id: @project.id,
              rule_type: rule_type,
              identifier: purl,
              seen_at: seen_at,
              blocked: blocked,
              warned: warned,
              severity: prevented_severity(rule, vulnerabilities)
            )
          end
        end
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e, project_id: @project.id)
      end

      # Highest non-excepted advisory severity ('none' maps to 'unknown'); nil for rule types without one.
      def prevented_severity(rule, vulnerabilities)
        return unless ::Security::DependencyFirewallPolicyRule.severity_carrying_types.include?(rule.type)

        rule.non_excepted_vulnerabilities(vulnerabilities).filter_map do |vuln|
          ::Enums::Vulnerability.severity_levels[::Enums::Vulnerability.parse_severity_level(vuln[:severity])]
        end.max
      end

      def nothing_evaluated?(results)
        results.all? { |result| ::Security::DependencyFirewallPolicies::Rule.non_evaluation_reason?(result[:reason]) }
      end

      # Surfaces the reason a package was allowed (bypass or exception) so the audit log can
      # describe it. Falls back to an empty result for a plain allow, keeping the generic message.
      def notable_allowed_result(results)
        results.find { |result| NOTABLE_ALLOWED_REASONS.include?(result[:reason]) } || {}
      end

      def response(status, result: nil)
        return ServiceResponse.success(payload: { status: status }) if result.nil?

        ServiceResponse.success(payload: { status: status, message: build_violation_message(result) })
      end

      def error_response(message, reason)
        ServiceResponse.error(message: message, reason: reason)
      end

      # Single line, as it becomes the reason in the evaluation response. Everything interpolated
      # is config-derived; a rule deriving `details` externally must sanitize it.
      def build_violation_message(result)
        base = "Package '#{@name}' violates '#{result[:policy_name]}' policy"
        exceeded = result.dig(:details, :exceeded)
        reason = result.dig(:details, :reason)
        return "#{base}: #{reason}" if exceeded.blank? && reason.present?
        return base if exceeded.blank?

        counts = ::Security::DependencyFirewallPolicies::RiskSeverityRule.format_exceeded(exceeded)

        "#{base}: vulnerability count #{'threshold'.pluralize(exceeded.size)} exceeded (#{counts})"
      end

      def audit(event_type, result)
        purl = build_purl

        CreateAuditEventsService.new(
          project: @project, purl: purl, operation: @operation,
          result: result, author: @current_user, event_type: event_type,
          session_id: @session_id
        ).execute
      end

      def audit_bypasses(results)
        AuditBypassesService.new(
          @project, current_user: @current_user, results: results, purl: build_purl,
          operation: @operation, session_id: @session_id
        ).execute
      end

      # Records block/warn/allow activity for the dependency firewall dashboard. rule_id is nil
      # for allowed outcomes that matched no rule. Best-effort: a counter failure must never
      # break package enforcement.
      def record_activity(outcome, result)
        rule_id = result[:matched_rule]&.rule_id

        ::Security::DependencyFirewallActivityStat.increment!(
          rule_id: rule_id,
          project_id: @project.id,
          outcome: outcome
        )
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e, project_id: @project.id, outcome: outcome, rule_id: rule_id)
      end

      def track_event(outcome, start_time)
        service_params = {
          operation: @operation,
          outcome: outcome,
          namespace: @project.namespace,
          cache_hit: cache_hit,
          runtime_ms: calculate_runtime_ms(start_time),
          purl: build_purl,
          session_id: @session_id
        }

        CreateEventService.new(@project, @current_user, service_params).execute
      end

      def build_purl
        "pkg:#{@pkg_type}/#{@name}@#{@version}"
      end

      # TODO: the work for this will be done as part of https://gitlab.com/gitlab-org/gitlab/-/work_items/588475
      def cache_hit
        false
      end

      def calculate_runtime_ms(start_time)
        ((Time.current - start_time) * 1000).to_i
      end
    end
  end
end
