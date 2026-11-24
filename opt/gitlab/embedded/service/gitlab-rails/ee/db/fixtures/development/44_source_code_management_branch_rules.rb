# frozen_string_literal: true

# Seeds the EE source code management tables that had neither a factory nor a fixture, so
# migrations touching them were never exercised by db:migrate:multi-version-upgrade.
#
# Uses `insert_all` so rows can carry the nulls model validations reject - a later NOT NULL
# migration needs something to trip on.
class Gitlab::Seeder::SourceCodeManagementBranchRules # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  SEEDED_BRANCH_NAME = 'seeded-protected-branch'

  attr_reader :protected_branch

  def initialize
    @protected_branch = ProtectedBranch.where.not(project_id: nil).order(:id).first ||
      create_protected_branch
  end

  def seed!
    return warn_missing_dependencies unless protected_branch && organization_id

    seed_organization_push_rules
    seed_branch_rules_approval_settings
    seed_required_code_owners_sections
  end

  private

  def warn_missing_dependencies
    warn "\nSkipping EE source code management seeds: no protected branch with an organization available"
  end

  # `16_protected_branches.rb` covers `Project.not_mass_generated` only, which a mass-inserted
  # seed leaves empty, so the branch these three tables hang off is created here when missing.
  def create_protected_branch
    project = Project.not_mass_generated.first || Project.first
    return if project.nil?

    ProtectedBranch.create!(project: project, name: SEEDED_BRANCH_NAME)
  end

  # Half the optional columns stay null so a later NOT NULL migration has both shapes present.
  def seed_organization_push_rules
    row = {
      organization_id: organization_id,
      max_file_size: 0,
      member_check: true,
      prevent_secrets: true,
      commit_committer_name_check: false,
      deny_delete_tag: true,
      reject_unsigned_commits: nil,
      commit_committer_check: nil,
      reject_non_dco_commits: nil,
      commit_message_regex: '\\AFix: ',
      branch_name_regex: nil,
      commit_message_negative_regex: nil,
      author_email_regex: '.*@example\\.com\\z',
      file_name_regex: nil,
      reject_unverified_commits: nil,
      created_at: now,
      updated_at: now
    }

    OrganizationPushRule.insert_all([row], unique_by: %i[organization_id])
    print '.'
  end

  def seed_branch_rules_approval_settings
    row = {
      protected_branch_id: protected_branch.id,
      project_id: protected_branch.project_id,
      prevent_author_approval: true,
      prevent_committer_approval: false,
      prevent_editing_approval_rules: true,
      require_reauthentication_to_approve: false,
      approval_removals: 1,
      created_at: now,
      updated_at: now
    }

    Projects::BranchRules::MergeRequestApprovalSetting.insert_all([row], unique_by: %i[protected_branch_id])
    print '.'
  end

  # No unique index on this table, so the guard is what keeps a re-run from inserting again.
  # The branch is project level, so the namespace side of the sharding key check stays null.
  def seed_required_code_owners_sections
    return if ProtectedBranch::RequiredCodeOwnersSection.exists?(protected_branch_id: protected_branch.id)

    rows = [
      { protected_branch_id: protected_branch.id, name: 'Seeded section',
        protected_branch_project_id: protected_branch.project_id, protected_branch_namespace_id: nil },
      { protected_branch_id: protected_branch.id, name: '',
        protected_branch_project_id: protected_branch.project_id, protected_branch_namespace_id: nil }
    ]

    ProtectedBranch::RequiredCodeOwnersSection.insert_all(rows)
    print '.'
  end

  # Inferred from the branch's project rather than looked up directly, which the
  # Gitlab/PreventOrganizationFirst cop requires.
  def organization_id
    @organization_id ||= protected_branch.project&.organization_id
  end

  def now
    @now ||= Time.current
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating EE source code management data"

  Gitlab::Seeder::SourceCodeManagementBranchRules.new.seed!
end
