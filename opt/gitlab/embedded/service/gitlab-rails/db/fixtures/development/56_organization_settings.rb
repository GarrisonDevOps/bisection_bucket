# frozen_string_literal: true

# Seeds the organization settings tables, which are empty in the upgrade stop dump, so migrations
# touching them were never exercised by db:migrate:multi-version-upgrade.
class Gitlab::Seeder::OrganizationSettings # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  attr_reader :organization

  def initialize
    @organization = ::Gitlab::DatabaseImporters::AdminOrganizationImporter.seeded_admin_organization
  end

  def seed!
    return warn_missing_dependencies unless organization

    seed_isolation
    seed_settings
  end

  private

  def warn_missing_dependencies
    warn "\nSkipping organization settings seeds: no seeded organization available"
  end

  # `isolated` stays false because `Key` reads `organization.not_isolated?` when it compares a key
  # against another organization's, and a seeded true would change that for the fixtures after it.
  def seed_isolation
    Organizations::OrganizationIsolation.create_with(isolated: false)
      .find_or_create_by!(organization: organization)
    print '.'
  end

  # The settings column is a schema validated jsonb written through `jsonb_accessor`, so this goes
  # through the model. The restricted levels are read from `ApplicationSetting`, not from here.
  def seed_settings
    setting = Organizations::OrganizationSetting.find_or_initialize_by(organization: organization)
    return if setting.persisted?

    setting.update!(
      restricted_visibility_levels: [Gitlab::VisibilityLevel::INTERNAL],
      default_group_visibility: Gitlab::VisibilityLevel::PRIVATE)
    print '.'
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating organization settings data"

  Gitlab::Seeder::OrganizationSettings.new.seed!
end
