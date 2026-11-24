# frozen_string_literal: true

module Security
  module ScanResultPolicies
    module PolicyViolationCommentGenerator
      include PolicyLogger

      private

      def generate_policy_bot_comment(merge_request)
        if running_violations?(merge_request)
          log_policy_evaluation('policy_bot_comment', 'Skipping policy bot comment while a violation is running',
            Labkit::Fields::GL_PROJECT_PATH => merge_request.project.full_path,
            merge_request_id: merge_request.id, merge_request_iid: merge_request.iid)
          return
        end

        return if bot_message_disabled?(merge_request)

        Security::GeneratePolicyViolationCommentWorker.perform_async(merge_request.id)
      end

      def running_violations?(merge_request)
        merge_request.running_scan_result_policy_violations.exists?
      end

      # To reduce the noise on the merge request, policies can opt out of the bot comment.
      # If any violated policy has the bot comment enabled, it will be generated.
      # If there is an existing comment, it will always be updated even if the violated policies opt out.
      def bot_message_disabled?(merge_request)
        return true if merge_request.project.archived?
        # Ensure to always trigger the worker to update the comment if it's already present on the merge request.
        # For example:
        #   - Previously, Policy A with bot comment enabled had a violation which generated a comment.
        #   - Now, only Policy B with bot comment disabled has a violation.
        #   - We need to trigger the worker to update the comment since it's outdated.
        return false if merge_request.policy_bot_comment.present?

        rules = violated_applicable_rules(merge_request)
        return false if rules.blank?

        rules.all? { |rule| rule.approval_policy_source&.bot_message_disabled? }
      end

      # Returns approval rules that are applicable to the target branch and have a matching violation.
      def violated_applicable_rules(merge_request)
        applicable_rules = merge_request.approval_rules.report_approver
                                        .applicable_to_branch(merge_request.target_branch)

        violated_ids = merge_request.scan_result_policy_violations.filter_map(&:approval_policy_rule_id).to_set

        applicable_rules.select { |rule| violated_ids.include?(rule.approval_policy_rule_id) }
      end
    end
  end
end
