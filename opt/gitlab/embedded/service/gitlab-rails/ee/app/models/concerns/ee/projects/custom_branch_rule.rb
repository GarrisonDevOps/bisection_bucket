# frozen_string_literal: true

module EE
  module Projects
    module CustomBranchRule
      def approval_project_rules
        raise NotImplementedError
      end

      def external_status_checks
        raise NotImplementedError
      end

      def any_rules?
        approval_project_rules.present? || external_status_checks.present?
      end
      alias_method :persisted?, :any_rules?

      def group_level?
        false
      end

      def created_at
        [
          *external_status_checks.map(&:created_at),
          *approval_project_rules.map(&:created_at)
        ].min
      end

      def updated_at
        [
          *external_status_checks.map(&:updated_at),
          *approval_project_rules.map(&:updated_at)
        ].max
      end
    end
  end
end
