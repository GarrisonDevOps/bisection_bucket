# frozen_string_literal: true

module EE
  module Gitlab
    module Checks
      class PushRuleCheck < ::Gitlab::Checks::BaseBulkChecker
        def validate!
          return unless push_rule.present? || project.jira_integration.present?

          check_tag_or_branch! if push_rule.present?
          check_jira_verification!

          nil
        end

        private

        def check_tag_or_branch!
          changes_access.single_change_accesses.each do |single_change_access|
            if single_change_access.tag_ref?
              PushRules::TagCheck.new(single_change_access).validate!
            elsif single_change_access.branch_ref?
              PushRules::BranchCheck.new(single_change_access).validate!
            end
          end
        end

        def check_jira_verification!
          ::Gitlab::Checks::PushRules::JiraVerificationCheck.new(changes_access).validate!
        end
      end
    end
  end
end
