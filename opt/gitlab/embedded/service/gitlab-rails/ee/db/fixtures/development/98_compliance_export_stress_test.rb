# frozen_string_literal: true

# Usage:
#
# Seed 20000 compliance statuses for export stress testing:
# FILTER=compliance_export_stress_test SEED_COMPLIANCE_EXPORT_STRESS_TEST=1 bundle exec rake db:seed_fu
#
# Customize count (default 20000):
# FILTER=compliance_export_stress_test SEED_COMPLIANCE_EXPORT_STRESS_TEST=1 STATUS_COUNT=5000 \
#   bundle exec rake db:seed_fu
#
# Use existing group:
# FILTER=compliance_export_stress_test SEED_COMPLIANCE_EXPORT_STRESS_TEST=1 GROUP_ID=123 bundle exec rake db:seed_fu

class Gitlab::Seeder::ComplianceExportStressTest # rubocop:disable Style/ClassAndModuleChildren -- this is a seed script
  BATCH_SIZE = 1000
  STATUSES = %w[pass pending fail].freeze
  FAIL_PENDING_STATUSES = %w[fail pending].freeze
  CONTROL_TRAITS = %i[
    project_visibility_not_internal
    default_branch_protected
    external
  ].freeze

  attr_reader :group, :status_count

  def initialize(group: nil, status_count: 20_000)
    @admin = Gitlab::DatabaseImporters::AdminOrganizationImporter.seeded_admin
    @status_count = status_count
    @group = group || create_group
  end

  def seed!
    puts "Creating compliance export stress test data with #{status_count} statuses..."

    framework = create_framework_with_requirements
    projects = create_projects(framework)
    create_requirement_statuses(projects, framework)

    puts "\nSuccessfully seeded #{status_count} compliance statuses in '#{group.full_path}'"
    puts "URL: #{Rails.application.routes.url_helpers.group_url(group)}"
    compliance_url = "#{Rails.application.routes.url_helpers.group_url(group)}/" \
      "-/security/compliance_dashboard/standards_adherence"
    puts "Compliance Status Report: #{compliance_url}"
  end

  private

  def create_group
    FactoryBot.create(
      :group,
      :public,
      name: "Compliance Export Test #{suffix}",
      path: "compliance-export-test-#{suffix}"
    )
  end

  def create_framework_with_requirements
    puts "Creating compliance framework with requirements..."

    framework = FactoryBot.create(
      :compliance_framework,
      namespace: @group,
      name: "Export Test Framework",
      description: "Framework for export stress testing",
      color: '#FF5733'
    )

    10.times do |i|
      requirement = FactoryBot.create(
        :compliance_requirement,
        framework: framework,
        name: "Requirement #{i + 1}",
        description: "Test requirement #{i + 1}"
      )

      2.times do |j|
        trait = CONTROL_TRAITS[((i * 2) + j) % CONTROL_TRAITS.length]
        FactoryBot.create(
          :compliance_requirements_control,
          trait,
          compliance_requirement: requirement
        )
      end
    end

    print "."
    framework
  end

  def create_projects(framework)
    projects_needed = (status_count.to_f / framework.compliance_requirements.count).ceil
    projects_needed = [projects_needed, 100].max

    puts "\nCreating #{projects_needed} projects across subgroups..."

    projects = []
    subgroups = create_subgroups(5)

    projects_needed.times do |i|
      subgroup = subgroups[i % subgroups.length]
      project = FactoryBot.create(
        :project,
        namespace: subgroup,
        creator: @admin,
        name: "Project #{i + 1}",
        visibility_level: @group.visibility_level
      )

      project.compliance_management_frameworks << framework
      projects << project

      print "." if (i + 1) % 50 == 0
    end

    puts " #{projects.count} projects created"
    projects
  end

  def create_subgroups(count)
    puts "Creating #{count} subgroups..."

    Array.new(count) do |i|
      FactoryBot.create(
        :group,
        parent: @group,
        name: "Subgroup #{i + 1}",
        path: "subgroup-#{suffix}-#{i + 1}",
        visibility_level: @group.visibility_level
      )
    end
  end

  def create_requirement_statuses(projects, framework)
    requirements = framework.compliance_requirements.to_a
    statuses_created = 0

    puts "Creating #{status_count} requirement compliance statuses..."

    projects.each do |project|
      requirements.each do |requirement|
        break if statuses_created >= status_count

        next if requirement.compliance_requirements_controls.empty?

        status = STATUSES.sample
        controls_count = requirement.compliance_requirements_controls.count

        create_requirement_status(project, requirement, status, controls_count)
        create_control_statuses(project, requirement, status)

        statuses_created += 1
        print "." if (statuses_created % 500) == 0
      end

      break if statuses_created >= status_count
    end

    puts "\n#{statuses_created} requirement statuses created"
  end

  def create_requirement_status(project, requirement, status, controls_count)
    FactoryBot.create(
      :project_requirement_compliance_status,
      project: project,
      compliance_requirement: requirement,
      compliance_framework: requirement.framework,
      pending_count: status == 'pending' ? 1 : 0,
      fail_count: status == 'fail' ? 1 : 0,
      pass_count: status == 'pass' ? controls_count : [controls_count - 1, 0].max,
      updated_at: rand(30).days.ago
    )
  end

  def create_control_statuses(project, requirement, overall_status)
    controls = requirement.compliance_requirements_controls.to_a
    failed_idx = rand(controls.length)

    controls.each_with_index do |control, idx|
      control_status = if FAIL_PENDING_STATUSES.include?(overall_status) && idx == failed_idx
                         overall_status
                       else
                         'pass'
                       end

      FactoryBot.create(
        :project_control_compliance_status,
        project: project,
        compliance_requirement: requirement,
        compliance_requirements_control: control,
        status: control_status
      )
    end
  end

  def suffix
    @suffix ||= Time.now.to_i
  end
end

Gitlab::Seeder.quiet do
  flag = 'SEED_COMPLIANCE_EXPORT_STRESS_TEST'

  if ENV[flag]
    group = ENV['GROUP_ID'] ? Group.find(ENV['GROUP_ID']) : nil
    status_count = (ENV['STATUS_COUNT'] || 20_000).to_i

    seeder = Gitlab::Seeder::ComplianceExportStressTest.new(group: group, status_count: status_count)
    seeder.seed!
  else
    puts "Skipped seeding compliance export stress test data."
    puts "Use the `#{flag}` environment variable to enable."
  end
end
