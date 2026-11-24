# frozen_string_literal: true

# Seeds the AI access tables, which are empty in the upgrade stop dump, so migrations touching
# them were never exercised by db:migrate:multi-version-upgrade.
class Gitlab::Seeder::OrganizationAiAccess # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  DEFAULT_RULE_ENTITY = 'duo_classic'
  GROUP_RULE_ENTITY = 'duo_agent_platform'

  attr_reader :organization, :root_group

  def initialize
    @organization = ::Gitlab::DatabaseImporters::AdminOrganizationImporter.seeded_admin_organization
    @root_group = Group.where(parent_id: nil).order(:id).first
  end

  def seed!
    seed_access_rules if root_group
    seed_foundational_agent_statuses if organization
    warn_missing_dependencies unless root_group && organization
  end

  private

  def warn_missing_dependencies
    warn "\nSkipping some AI access seeds: no root group or no seeded organization available"
  end

  # `through_namespace_id` is nullable and carries the default rule, so one row leaves it unset.
  # Both entities come from the inclusion list the `Ai::FeatureAccessRuleable` concern enforces.
  def seed_access_rules
    access_rule(nil, DEFAULT_RULE_ENTITY)
    access_rule(root_group, GROUP_RULE_ENTITY)
  end

  # A through namespace must sit under the root namespace, which a root group does for itself.
  def access_rule(through_namespace, accessible_entity)
    Ai::NamespaceFeatureAccessRule.find_or_create_by!(
      root_namespace: root_group, through_namespace: through_namespace, accessible_entity: accessible_entity)
    print '.'
  end

  # `reference` is validated against the system defined agent list, which is a constant rather than
  # a table, so it is read off that list instead of written as a literal that could drift from it.
  def seed_foundational_agent_statuses
    Ai::FoundationalChatAgent.all.first(2).zip([true, false]).each do |agent, enabled|
      Ai::OrganizationFoundationalAgentStatus.create_with(enabled: enabled)
        .find_or_create_by!(organization: organization, reference: agent.reference)
      print '.'
    end
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating organization AI access data"

  Gitlab::Seeder::OrganizationAiAccess.new.seed!
end
