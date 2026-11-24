# frozen_string_literal: true

# Seeds the attestation and composer metadata tables, which are empty in the upgrade stop dump, so
# migrations touching them were never exercised by db:migrate:multi-version-upgrade.
class Gitlab::Seeder::SupplyChainAttestations # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  SUBJECT_DIGEST = ('a' * 64).freeze
  PREDICATE_TYPE = 'https://slsa.dev/provenance/v1'
  TARGET_SHA = ('b' * 40).freeze
  PACKAGE_NAME = 'seeded/composer-package'
  PACKAGE_VERSION = '1.0.0'

  # Each table hangs off a different parent, so each one is guarded, and named, on its own.
  def seed!
    seed_attestation
    seed_composer_metadatum
  end

  private

  def project
    @project ||= Project.not_mass_generated.first
  end

  # A successful attestation needs a file the uploader can resolve, which a seeded row cannot have,
  # so this takes the error status, the one state that validation does not apply to.
  def seed_attestation
    return warn "\nSkipping attestation seed: no project available" if project.nil?
    return if SupplyChain::Attestation.exists?(
      project_id: project.id, subject_digest: SUBJECT_DIGEST, predicate_kind: :provenance)

    SupplyChain::Attestation.create!(
      project: project, status: :error, predicate_kind: :provenance,
      predicate_type: PREDICATE_TYPE, subject_digest: SUBJECT_DIGEST)
    print '.'
  end

  # The metadatum hangs off a Composer package specifically, and the fixture that seeds those only
  # runs behind SEED_COMPOSER, so this keeps one of its own rather than reusing whichever package
  # the instance already has, whose metadata it would otherwise fabricate.
  # `version_cache_sha` is nullable and stays unset.
  def seed_composer_metadatum
    package = composer_package
    return warn "\nSkipping composer metadatum seed: no composer package available" if package.nil?
    return if Packages::Composer::Metadatum.exists?(package_id: package.id)

    Packages::Composer::Metadatum.create!(
      package: package, project_id: package.project_id,
      target_sha: TARGET_SHA, composer_json: { 'name' => package.name })
    print '.'
  end

  def composer_package
    Packages::Composer::Sti::Package.find_by(name: PACKAGE_NAME) || create_composer_package
  end

  def create_composer_package
    return if project.nil?

    Packages::Composer::Sti::Package.create!(
      project: project, name: PACKAGE_NAME, version: PACKAGE_VERSION,
      creator: ::Gitlab::DatabaseImporters::AdminOrganizationImporter.seeded_admin)
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating supply chain attestation data"

  Gitlab::Seeder::SupplyChainAttestations.new.seed!
end
