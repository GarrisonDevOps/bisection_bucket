# frozen_string_literal: true

module MergeRequests
  class ApprovalGroupedCodeOwnerRule < ::ApprovalWrappedCodeOwnerRule
    attr_reader :wrapped_rules

    def initialize(merge_request, wrapped_rules)
      @wrapped_rules = wrapped_rules.sort_by(&:id)
      super(merge_request, @wrapped_rules.first.approval_rule)
    end

    def patterns
      wrapped_rules.map(&:name)
    end

    def name
      return section if wrapped_rules.many? && section != ::Gitlab::CodeOwners::Section::DEFAULT

      patterns.join(', ')
    end

    def users
      wrapped_rules.flat_map(&:users).uniq
    end
    strong_memoize_attr :users

    def groups
      ::Group.id_in(wrapped_rules.flat_map { |rule| rule.groups.map(&:id) }.uniq)
    end
    strong_memoize_attr :groups

    def approvals_required
      wrapped_rules.map(&:approvals_required).max
    end

    def approvals_left
      wrapped_rules.map(&:approvals_left).max
    end

    def approved?
      wrapped_rules.all?(&:approved?)
    end

    def invalid_rule?
      wrapped_rules.any?(&:invalid_rule?)
    end
  end
end
