# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class CreateWarnModeApprovalAuditEventService
      include Gitlab::Utils::StrongMemoize

      AUDIT_EVENT = 'policy_warn_mode_merge_request_approval'

      def initialize(merge_request, user)
        @merge_request = merge_request
        @project = merge_request.project
        @user = user
      end

      def execute
        overrides = ::Security::ScanResultPolicies::ApprovalSettingsOverrides.new(
          project: project,
          warn_mode_policies: applicable_warn_mode_policies,
          enforced_policies: enforced_policies
        ).all

        return if overrides.empty?

        create_security_policy_bot! unless project.security_policy_bot

        ::AuditEvents::ProjectAuditEvent.transaction do
          ::Gitlab::Audit::Auditor.audit(audit_context) do
            overrides.each do |override|
              case override.attribute
              when :prevent_approval_by_author
                push_author_approved_event(override) if author_approved?
              when :prevent_approval_by_commit_author
                push_commit_author_approved_event(override) if commit_author_approved?
              when :require_password_to_approve
                push_password_required_event(override)
              end
            end
          end
        end
      end

      private

      attr_reader :merge_request,
        :project,
        :user

      def push_author_approved_event(override)
        push_audit_events(override, "The merge request author approved their own merge request")
      end

      def push_commit_author_approved_event(override)
        push_audit_events(override, "A user approved the merge request that they also committed to")
      end

      def push_password_required_event(override)
        push_audit_events(override, "A user approved the merge request without reauthenticating")
      end

      def push_audit_events(override, message)
        policies_by_project = override.security_policies.group_by(&:security_policy_management_project)

        policies_by_project.each do |security_policy_management_project, policies|
          policy_names = policies.map(&:name).join(", ")
          reference = merge_request.to_reference(full: true)

          connector = "which would have been prevented by the following security policies in warn mode:"

          merge_request.push_audit_event({
            message: "In merge request (#{reference}), #{message} #{connector} #{policy_names}",
            scope: security_policy_management_project
          }, after_commit: false)
        end
      end

      def author_approved?
        user == merge_request.author
      end

      def commit_author_approved?
        user.in?(merge_request.commits(load_from_gitaly: true).committers)
      end

      # Gitlab::Audit::Auditor expects scope key in the initial context in `initialize` method
      # but allows to override the params in `build_event` method (received through `push_audit_event` params:
      # * https://gitlab.com/gitlab-org/gitlab/-/blob/6b956610b3282a0bc84c416d78ca2dd6bd2736f8/lib/gitlab/audit/auditor.rb#L73
      # * https://gitlab.com/gitlab-org/gitlab/-/blob/6b956610b3282a0bc84c416d78ca2dd6bd2736f8/lib/gitlab/audit/auditor.rb#L186
      def audit_context
        {
          name: AUDIT_EVENT,
          target: merge_request,
          scope: project,
          author: project.security_policy_bot
        }
      end

      def create_security_policy_bot!
        Security::Orchestration::CreateBotService.new(project, nil, skip_authorization: true).execute.user
      end

      def applicable_warn_mode_policies
        merge_request_approval_policies.select(&:warn_mode?)
      end

      def enforced_policies
        merge_request_approval_policies.reject(&:warn_mode?)
      end

      def merge_request_approval_policies
        merge_request
          .security_policies_through_violations
          .type_approval_policy
          .including_security_policy_management_project
      end
      strong_memoize_attr :merge_request_approval_policies
    end
  end
end
