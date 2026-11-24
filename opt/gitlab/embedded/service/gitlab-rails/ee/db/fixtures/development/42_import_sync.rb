# frozen_string_literal: true

# Seeds the import_sync_* tables added for the GitHub continuous-sync port, which had
# neither a factory nor a fixture, so migrations touching them were never exercised by
# db:migrate:multi-version-upgrade. The feature itself is behind the default-off
# github_continuous_import flag; this only needs one row per table to exist.
class Gitlab::Seeder::ImportSync # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  attr_reader :project, :user, :issue

  def initialize
    # Reuses an issue other fixtures already created, on its own project, rather
    # than creating one here: Issue.create! carries enough GitLab-specific setup
    # (work item type, namespace, etc.) that constructing one on an arbitrary
    # project is fragile outside the normal creation paths.
    @issue = Issue.first
    @project = issue&.project || Project.first
    @user = User.first
  end

  def seed!
    return warn_missing_dependencies unless project && user

    repository = seed_repository
    seed_repository_state(repository)
    seed_external_object(repository) if issue
    seed_user_credential(repository)
  end

  private

  def warn_missing_dependencies
    warn "\nSkipping import sync seeds: no project or user available"
  end

  def seed_repository
    repository = Import::Sync::Repository.find_or_create_by!(project: project) do |repository|
      repository.connected_by_user = user
      repository.authority_state = :provider_canonical
      repository.provider = :github
      repository.provider_installation_xid = 1
      repository.provider_account_xid = 1
      repository.provider_account_login = 'seeded-github-account'
      repository.provider_repository_xid = project.id
      repository.provider_repository_node_id = "R_seed_#{project.id}"
      repository.provider_full_name = "seeded-github-account/#{project.path}"
      repository.provider_default_branch = project.default_branch || 'main'
    end
    print '.'
    repository
  end

  def seed_repository_state(repository)
    Import::Sync::RepositoryState.find_or_create_by!(repository: repository, domain: :source) do |state|
      state.state = :current
    end
    print '.'
  end

  def seed_user_credential(repository)
    Import::UserCredential.find_or_create_by!(
      user: user,
      provider: :github,
      provider_host: 'github.com',
      provider_account_xid: repository.provider_account_xid
    ) do |credential|
      credential.access_token = 'gho_seeded_token'
    end
    print '.'
  end

  def seed_external_object(repository)
    Import::Sync::ExternalObject.find_or_create_by!(repository: repository, kind: :issue, issue: issue) do |object|
      object.provider_object_xid = issue.id
      object.provider_updated_at = Time.current
    end
    print '.'
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating import sync data"

  Gitlab::Seeder::ImportSync.new.seed!
rescue StandardError => e
  warn "\nError seeding import sync data: #{e}"
end
