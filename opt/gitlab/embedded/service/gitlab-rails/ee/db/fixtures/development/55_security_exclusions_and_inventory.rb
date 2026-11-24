# frozen_string_literal: true

# Seeds security exclusion and inventory tables that are empty in the upgrade stop dump, so
# migrations touching them were never exercised by db:migrate:multi-version-upgrade.
class Gitlab::Seeder::SecurityExclusionsAndInventory # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  CATEGORY_NAME = 'Seeded business impact'
  ATTRIBUTE_NAME = 'Seeded mission critical'
  LONG_VALUE = 'a' * 255

  attr_reader :project, :namespace, :root_group

  # A subgroup project is preferred so `traversal_ids` carries more than the root id and the
  # attribute's namespace is genuinely a different record from the project's own.
  def initialize
    @project = Project.where(namespace_id: Group.where.not(parent_id: nil).select(:id)).order(:id).first ||
      Project.where(namespace_id: Group.select(:id)).order(:id).first
    @namespace = @project&.namespace
    @root_group = @namespace&.root_ancestor
  end

  def seed!
    return warn_missing_dependencies unless project

    seed_group_exclusions
    seed_project_exclusions
    seed_project_to_security_attribute
    seed_namespace_statistics
  end

  private

  def warn_missing_dependencies
    warn "\nSkipping security exclusion seeds: no project under a group available"
  end

  # Neither exclusion table has a natural unique key, so each row is guarded on the values that
  # identify it. `description` is nullable and stays unset on one row of each pair.
  def seed_group_exclusions
    exclusion(Security::GroupSecurityExclusion, { group: root_group }, :path,
      'spec/fixtures/**', description: 'Seeded path exclusion')
    exclusion(Security::GroupSecurityExclusion, { group: root_group }, :raw_value,
      LONG_VALUE, active: false)
  end

  def seed_project_exclusions
    exclusion(Security::ProjectSecurityExclusion, { project: project }, :regex_pattern,
      'glpat-[0-9a-zA-Z_-]{20}', description: 'Seeded regex exclusion')
    exclusion(Security::ProjectSecurityExclusion, { project: project }, :rule,
      LONG_VALUE, active: false)
  end

  def exclusion(model, owner, type, value, description: nil, active: true)
    model.create_with(description: description, active: active)
      .find_or_create_by!(owner.merge(scanner: :secret_push_protection, type: type, value: value))
    print '.'
  end

  # The attribute has to hang off the project's root ancestor, which `same_root_ancestor` checks,
  # and the connection carries the project namespace's own ids the way the update service does.
  def seed_project_to_security_attribute
    Security::ProjectToSecurityAttribute.create_with(traversal_ids: namespace.traversal_ids)
      .find_or_create_by!(project: project, security_attribute: security_attribute)
    print '.'
  end

  # Both lookups are keyed on the columns their partial unique index covers and scoped the way the
  # application reads them, so a soft deleted row is replaced rather than handed back as current.
  def security_attribute
    @security_attribute ||= Security::Attribute.not_deleted.create_with(
      namespace: root_group, description: 'Seeded attribute', color: '#6699cc',
      editable_state: :editable, template_type: :mission_critical
    ).find_or_create_by!(security_category: security_category, name: ATTRIBUTE_NAME)
  end

  def security_category
    @security_category ||= Security::Category.not_deleted.create_with(
      description: 'Seeded category', editable_state: :editable, multiple_selection: false,
      template_type: :business_impact
    ).find_or_create_by!(namespace: root_group, name: CATEGORY_NAME)
  end

  # `total` is the sum of the severity counters, which is how the ingestion task builds the row.
  # The second namespace keeps every counter at zero, the state a group with no findings holds.
  def seed_namespace_statistics
    statistic(root_group, critical: 2, high: 3, medium: 1, low: 4, unknown: 1, info: 5)
    statistic(namespace) unless namespace.id == root_group.id
  end

  def statistic(group, **counts)
    Vulnerabilities::NamespaceStatistic.create_with(
      counts.merge(total: counts.values.sum, traversal_ids: group.traversal_ids)
    ).find_or_create_by!(namespace_id: group.id)
    print '.'
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating security exclusion and inventory data"

  Gitlab::Seeder::SecurityExclusionsAndInventory.new.seed!
end
