# frozen_string_literal: true

# Seeds approval_merge_request_rule_sources, which had no fixture, so migrations touching it were
# never exercised by db:migrate:multi-version-upgrade. The table links a merge request approval
# rule to the project rule it was copied from; neither parent is reliably seeded.
class Gitlab::Seeder::CodeReviewApprovalRuleSources # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  MERGE_REQUESTS_TO_SEED = 3

  attr_reader :project

  def initialize
    @project = MergeRequest.first&.target_project
  end

  def seed!
    return warn_missing_dependencies unless project

    project_rule = project.approval_rules.regular.first || create_project_rule
    return unless project_rule

    # approval_merge_request_rule_id is unique, so each row needs its own merge request rule.
    rows = merge_request_rules.map do |rule|
      {
        approval_merge_request_rule_id: rule.id,
        approval_project_rule_id: project_rule.id,
        project_id: project.id
      }
    end

    ApprovalMergeRequestRuleSource.insert_all(rows, unique_by: :approval_merge_request_rule_id) if rows.any?
    print '.'
  end

  private

  def warn_missing_dependencies
    warn "\nSkipping approval rule source seeds: no merge request available"
  end

  def merge_request_rules
    project.merge_requests.opened.order(:id).limit(MERGE_REQUESTS_TO_SEED).filter_map do |merge_request|
      merge_request.approval_rules.regular.first || create_merge_request_rule(merge_request)
    end
  end

  def create_project_rule
    project.approval_rules.create!(name: 'Seeded project approval rule', approvals_required: 1)
  rescue StandardError => e
    warn "\nCould not create a project approval rule: #{e.message}"
    nil
  end

  def create_merge_request_rule(merge_request)
    merge_request.approval_rules.create!(name: 'Seeded approval rule', approvals_required: 1)
  rescue StandardError => e
    warn "\nCould not create an approval rule for merge request #{merge_request.id}: #{e.message}"
    nil
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating approval rule source data"

  Gitlab::Seeder::CodeReviewApprovalRuleSources.new.seed!
rescue StandardError => e
  warn "\nError seeding approval rule source data: #{e}"
end
