# frozen_string_literal: true

# Seeds approval_merge_request_rules_users, which had neither a factory nor a fixture, so
# migrations touching it were never exercised by db:migrate:multi-version-upgrade. The parent
# approval rule is itself unseeded, so one is created when missing.
class Gitlab::Seeder::CodeReviewApprovalRules # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  attr_reader :merge_request, :user

  def initialize
    @merge_request = MergeRequest.first
    @user = User.first
  end

  def seed!
    return warn_missing_dependencies unless merge_request && user

    rule = ApprovalMergeRequestRule.first || create_approval_rule
    return unless rule

    # Rows differ on user because (approval_merge_request_rule_id, user_id) is unique. project_id
    # is nil in memory for a freshly created rule; the table's sync trigger then fills it from the
    # parent rule's row, so the value always matches the parent.
    rows = User.order(:id).limit(2).map do |approver|
      {
        approval_merge_request_rule_id: rule.id,
        user_id: approver.id,
        project_id: rule.project_id
      }
    end

    ApprovalMergeRequestRulesUser.insert_all(rows) if rows.any?
    print '.'
  end

  private

  def warn_missing_dependencies
    warn "\nSkipping approval rule user seeds: no merge request or user available"
  end

  def create_approval_rule
    ApprovalMergeRequestRule.create!(
      merge_request: merge_request,
      name: 'Seeded approval rule',
      approvals_required: 1
    )
  rescue StandardError => e
    warn "\nCould not create an approval rule: #{e.message}"
    nil
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating approval rule user data"

  Gitlab::Seeder::CodeReviewApprovalRules.new.seed!
rescue StandardError => e
  warn "\nError seeding approval rule user data: #{e}"
end
