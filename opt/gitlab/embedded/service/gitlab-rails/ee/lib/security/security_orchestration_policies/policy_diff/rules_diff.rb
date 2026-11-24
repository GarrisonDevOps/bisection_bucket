# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    module PolicyDiff
      class RulesDiff
        attr_accessor :created, :updated, :deleted

        def self.from_json(json)
          new.tap do |rules_diff|
            rules_diff.created = construct_rule_diff(json[:created])
            rules_diff.updated = construct_rule_diff(json[:updated])
            rules_diff.deleted = construct_rule_diff(json[:deleted])
          end
        end

        def self.construct_rule_diff(rules)
          Array.wrap(rules).map do |rule|
            RuleDiff.new(id: rule[:id], from: rule[:from], to: rule[:to])
          end
        end

        def initialize
          @created = []
          @updated = []
          @deleted = []
        end

        def add_created_rule(new_rule)
          created << RuleDiff.new(id: nil, from: nil, to: new_rule)
        end

        def add_deleted_rule(deleted_rule)
          deleted << RuleDiff.new(id: deleted_rule.id, from: deleted_rule, to: nil)
        end

        def add_updated_rule(updated_rule, from, to)
          updated << RuleDiff.new(id: updated_rule.id, from: from, to: to)
        end

        def any_changes?
          created.any? || updated.any? || deleted.any?
        end

        def to_h
          {
            created: created.map(&:to_h),
            updated: updated.map(&:to_h),
            deleted: deleted.map(&:to_h)
          }
        end
      end
    end
  end
end
