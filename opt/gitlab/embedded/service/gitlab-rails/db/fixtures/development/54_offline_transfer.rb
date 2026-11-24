# frozen_string_literal: true

# Seeds the offline transfer tables, which are empty in the upgrade stop dump, so migrations
# touching them were never exercised by db:migrate:multi-version-upgrade.
class Gitlab::Seeder::OfflineTransfer # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  BUCKET = 'seeded-offline-transfer-bucket'
  PLACEHOLDER = 'placeholder'
  # Validated to carry a scheme and host and nothing else, and not to be a known import source.
  SOURCE_HOSTNAME = 'https://seeded-source.example.com'

  attr_reader :organization, :user

  def initialize
    @user = ::Gitlab::DatabaseImporters::AdminOrganizationImporter.seeded_admin
    @organization = @user && ::Gitlab::DatabaseImporters::AdminOrganizationImporter.seeded_admin_organization
  end

  def seed!
    return warn_missing_parents unless user && organization

    seed_configuration(seed_export)
  end

  private

  # Naming the absent parent keeps a run that seeds nothing from reading like a run that worked.
  def warn_missing_parents
    warn "\nSkipping offline transfer seeds: no seeded admin or organization available"
  end

  # The state machine sends mail and tracks events on a transition, so the row is left in the
  # state it is created in. `source_hostname` is ignored by the model and stays unset.
  def seed_export
    export = ::Import::Offline::Export.find_by(user_id: user.id, organization_id: organization.id)
    return export if export

    export = ::Import::Offline::Export.create!(user: user, organization: organization, status: :created)
    print '.'

    export
  end

  # `object_storage_credentials` is encrypted and schema validated per provider, so this goes
  # through the model. The check constraint allows an export or a bulk import, never both.
  def seed_configuration(export)
    return if ::Import::Offline::Configuration.exists?(offline_export_id: export.id)

    ::Import::Offline::Configuration.create!(
      organization: organization, offline_export: export, provider: :aws,
      bucket: BUCKET, source_hostname: SOURCE_HOSTNAME,
      object_storage_credentials: {
        aws_access_key_id: PLACEHOLDER,
        aws_secret_access_key: PLACEHOLDER,
        region: 'eu-west-1',
        path_style: false
      })
    print '.'
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating offline transfer data"

  Gitlab::Seeder::OfflineTransfer.new.seed!
end
