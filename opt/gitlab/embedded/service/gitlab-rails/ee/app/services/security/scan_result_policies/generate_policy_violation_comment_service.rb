# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class GeneratePolicyViolationCommentService
      include ::Gitlab::ExclusiveLeaseHelpers
      include ::Gitlab::Utils::StrongMemoize

      LOCK_SLEEP_SEC = 0.5.seconds

      attr_reader :merge_request, :project

      def initialize(merge_request)
        @merge_request = merge_request
        @project = merge_request.project
      end

      def execute
        in_lock(exclusive_lock_key, sleep_sec: LOCK_SLEEP_SEC) do
          break ServiceResponse.success if comment.body.blank?

          note = if needs_recreate_as_internal?
                   recreate_comment_as_internal
                 elsif existing_comment
                   Notes::UpdateService.new(project, bot_user, note_params(comment.body)).execute(existing_comment)
                 else
                   create_comment(confidential: internal_comment?)
                 end

          if note.nil? || note.persisted?
            ServiceResponse.success
          else
            ServiceResponse.error(message: note.errors.full_messages)
          end
        end
      rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
        ServiceResponse.error(message: ['Failed to obtain an exclusive lock'])
      end

      private

      def exclusive_lock_key
        "#{self.class.name.underscore}::merge_request_id:#{merge_request.id}"
      end

      def comment
        @comment ||= PolicyViolationComment.new(
          existing_comment,
          merge_request,
          enabled_violated_policy_ids: enabled_violated_policy_ids
        ).tap do |violation_comment|
          initialize_comment(violation_comment)
        end
      end

      def initialize_comment(violation_comment)
        violated_rules = enabled_violated_violations.filter_map { |violation| find_rule_for_violation(violation) }

        violation_comment.clear_report_types
        violated_rules.each do |rule|
          requires_approval = rule.approvals_required > 0
          violation_comment.add_report_type(rule.report_type, requires_approval)
        end
      end

      def enabled_violated_violations
        merge_request.scan_result_policy_violations.including_approval_policy_rules_with_policies
          .reject(&:bot_message_disabled?)
      end
      strong_memoize_attr :enabled_violated_violations

      def enabled_violated_policy_ids
        enabled_violated_violations.filter_map { |violation| approval_policy_source_id_for(violation) }.to_set
      end
      strong_memoize_attr :enabled_violated_policy_ids

      def internal_comment?
        enabled_violated_violations.any?(&:bot_message_internal?)
      end
      strong_memoize_attr :internal_comment?

      # `Note#confidential` cannot be changed on an existing note, so widening visibility to
      # internal requires destroying and recreating the comment. We never narrow the other way
      # (internal -> public): once a policy marks a comment internal, it stays internal, since
      # exposing previously-internal content is a stronger, less reversible mistake than a
      # comment staying more private than currently configured.
      def needs_recreate_as_internal?
        existing_comment.present? && !existing_comment.confidential? && internal_comment?
      end

      # Destroying loses any human replies in the comment's discussion thread; this is the
      # accepted trade-off for using the platform's normal (non-bypassing) note lifecycle
      # instead of forcing a change to `Note#confidential` outside of note creation.
      def recreate_comment_as_internal
        Notes::DestroyService.new(project, bot_user).execute(existing_comment)
        @existing_comment = nil
        create_comment(confidential: true)
      end

      def create_comment(confidential:)
        create_params = note_params(comment.body).merge(confidential: confidential)
        Notes::CreateService.new(project, bot_user, create_params).execute
      end

      def find_rule_for_violation(violation)
        rules_by_source_id[approval_policy_source_id_for(violation)]
      end

      def approval_policy_source_id_for(violation)
        violation.approval_policy_rule_id || violation.scan_result_policy_id
      end

      def rules_by_source_id
        applicable_rules.index_by { |rule| rule.approval_policy_source&.id }.except(nil)
      end
      strong_memoize_attr :rules_by_source_id

      def applicable_rules
        merge_request.approval_rules.applicable_to_branch(merge_request.target_branch)
      end
      strong_memoize_attr :applicable_rules

      def existing_comment
        @existing_comment ||= merge_request.policy_bot_comment
      end

      def bot_user
        @bot_user ||= Users::Internal.in_organization(project.organization).security_bot
      end

      def note_params(body)
        {
          note: body,
          noteable: merge_request,
          skip_touch_noteable: true
        }
      end
    end
  end
end
