# frozen_string_literal: true

module Security
  module DependencyFirewall
    class CreateAuditEventsService
      DEFINED_EVENT_TYPES = %i[allowed blocked warned].freeze

      def self.operation_label(operation)
        case operation
        when EnforcementService::PACKAGE_DOWNLOAD then 'package download'
        when EnforcementService::PACKAGE_UPLOAD   then 'package upload'
        when EnforcementService::CONTAINER_PULL   then 'container pull'
        when EnforcementService::CONTAINER_PUSH   then 'container push'
        else 'operation'
        end
      end

      def initialize(project:, purl:, operation:, result:, author:, event_type:, session_id: nil)
        @project    = project
        @purl       = purl
        @operation  = operation
        @result     = result
        @author     = author
        @event_type = event_type
        @session_id = session_id
      end

      def execute
        return unless @project

        raise ArgumentError, "Unknown DependencyFirewall event_type: #{@event_type.inspect}" \
          unless @event_type.in?(DEFINED_EVENT_TYPES)

        ::Gitlab::Audit::Auditor.audit(audit_context)
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e, project_id: @project.id, purl: @purl)
      end

      private

      def audit_context
        {
          name: event_name,
          author: @author || ::Gitlab::Audit::UnauthenticatedAuthor.new,
          scope: @project,
          target: @project,
          message: build_audit_message,
          additional_details: additional_details
        }
      end

      def additional_details
        details = {
          purl: @purl,
          operation: operation_label,
          matched_rule: @result[:matched_rule]&.to_h,
          policy_name: @result[:policy_name],
          exceeded_severities: @result.dig(:details, :exceeded),
          policies_evaluated: @result[:policies_evaluated]
        }
        # An absent key rather than a null value: see Security::DependencyFirewall::SessionId.
        details[:session_id] = @session_id if @session_id

        details
      end

      def event_name
        case @event_type
        when :allowed then 'dependency_firewall_allowed'
        when :blocked then 'dependency_firewall_blocked'
        when :warned  then 'dependency_firewall_warned'
        end
      end

      def build_audit_message
        policy_name = @result[:policy_name] || 'dependency firewall policy'

        case @event_type
        when :allowed
          "Allowed #{operation_label} for dependency #{@purl}#{allowed_reason_suffix}"
        when :blocked
          "Blocked #{operation_label} for dependency #{@purl} due to #{policy_name} violation" \
            "#{rule_detail_suffix}"
        when :warned
          "Warning: policy matched for #{operation_label} of dependency #{@purl} (#{policy_name})" \
            "#{rule_detail_suffix}"
        end
      end

      def allowed_reason_suffix
        policy_name = @result[:policy_name]

        case @result[:reason]
        when :user_bypassed  then %( (bypassed by user via "#{policy_name}"))
        when :token_bypassed then %( (bypassed by access token via "#{policy_name}"))
        when :exception      then %( (allowed by "#{policy_name}" exception))
        else policies_suffix
        end
      end

      def rule_detail_suffix
        exceeded = @result.dig(:details, :exceeded)
        return exceeded_suffix(exceeded) if exceeded.present?

        rule = @result[:matched_rule]
        return '' unless rule&.license_rule?

        names = rule.denied_names
        names.any? ? " (licenses: #{names.join(', ')})" : ''
      end

      def exceeded_suffix(exceeded)
        " (#{::Security::DependencyFirewallPolicies::RiskSeverityRule.format_exceeded(exceeded)})"
      end

      def policies_suffix
        policies_count = @result[:policies_evaluated]
        return '' unless policies_count

        " (#{policies_count} #{'policy'.pluralize(policies_count)} evaluated)"
      end

      def operation_label
        self.class.operation_label(@operation)
      end
    end
  end
end
