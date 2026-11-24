# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class ApprovalSettings
      def initialize(approval_settings)
        @approval_settings = approval_settings || {}
      end

      def prevent_approval_by_author
        approval_settings[:prevent_approval_by_author]
      end

      def prevent_approval_by_commit_author
        approval_settings[:prevent_approval_by_commit_author]
      end

      def remove_approvals_with_new_commit
        approval_settings[:remove_approvals_with_new_commit]
      end

      def require_password_to_approve
        approval_settings[:require_password_to_approve]
      end

      def block_branch_modification
        approval_settings[:block_branch_modification]
      end

      def prevent_pushing_and_force_pushing
        approval_settings[:prevent_pushing_and_force_pushing]
      end

      def prevent_editing_approval_rules
        approval_settings[:prevent_editing_approval_rules]
      end

      def block_group_branch_modification
        approval_settings[:block_group_branch_modification]
      end

      def block_group_branch_modification_enabled?
        case block_group_branch_modification
        when true then true
        when false then false
        when Hash then block_group_branch_modification[:enabled] == true
        else false
        end
      end

      def block_group_branch_modification_exception_group_ids
        setting = block_group_branch_modification
        return [] unless setting.is_a?(Hash)

        Array.wrap(setting[:exceptions]).filter_map { |exception| exception[:id] }
      end

      private

      attr_reader :approval_settings
    end
  end
end
