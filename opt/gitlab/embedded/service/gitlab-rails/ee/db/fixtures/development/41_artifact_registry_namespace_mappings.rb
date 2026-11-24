# frozen_string_literal: true

# Seeds one Artifact Registry namespace mapping per organization, mirroring the
# one-row-per-organization shape the provisioning flow (monolith/S10) writes.
# The UUID is a placeholder: no local Artifact Registry service is provisioned
# in development. It is still minted as a UUIDv7, the version AR generates for
# every primary key, because the grant path sends a namespace-targeted id on to
# IAM, whose proto CEL regex accepts UUIDv7 alone.
class Gitlab::Seeder::ArtifactRegistryNamespaceMappings # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  def seed!
    existing_organization_ids = ArtifactRegistry::NamespaceMapping.distinct.pluck(:organization_id).to_set

    Organizations::Organization.find_each do |organization|
      next if existing_organization_ids.include?(organization.id)

      ArtifactRegistry::NamespaceMapping.create!(
        organization: organization,
        ar_namespace_id: Gitlab::Utils.uuid_v7
      )

      print '.' # seeder progress output, matching sibling fixtures
    end
  end
end

Gitlab::Seeder.quiet do
  Gitlab::Seeder::ArtifactRegistryNamespaceMappings.new.seed!
end
