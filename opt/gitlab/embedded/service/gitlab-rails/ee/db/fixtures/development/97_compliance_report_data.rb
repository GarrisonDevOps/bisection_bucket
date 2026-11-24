# frozen_string_literal: true

require './spec/support/sidekiq_middleware'
require 'active_support/testing/time_helpers'

# Usage:
#
# Seed specific group:
# FILTER=compliance_report_data SEED_COMPLIANCE_REPORT_DATA=1 GROUP_ID=10 bundle exec rake db:seed_fu
#
# Seed new group:
# FILTER=compliance_report_data SEED_COMPLIANCE_REPORT_DATA=1 bundle exec rake db:seed_fu

class Gitlab::Seeder::ComplianceReportData # rubocop:disable Style/ClassAndModuleChildren -- this is a seed script
  include ActiveSupport::Testing::TimeHelpers

  attr_reader :group

  def initialize(group)
    @admin = Gitlab::DatabaseImporters::AdminOrganizationImporter.seeded_admin
    @group = group || create_group
    @projects_count_in_main_group = 75
    @projects_count_in_subgroup = 75
    @projects = []
  end

  def seed!
    Sidekiq::Worker.skipping_transaction_check do
      Sidekiq::Testing.inline! do
        Gitlab::ExclusiveLease.skipping_transaction_check do
          red_framework = create_compliance_framework('Red framework', with_requirements: true, color: '#DC143C')
          green_framework = create_compliance_framework('Green framework', with_requirements: true, color: '#009966')
          create_compliance_framework('Blue framework', color: '#6699CC')
          (1..@projects_count_in_main_group).each do |project_no|
            project = FactoryBot.create(:project, :repository, namespace: @group, creator: @admin,
              name: "#{FFaker::Product.product_name}-#{project_no}", visibility_level: @group.visibility_level)

            @projects << project
            [red_framework, green_framework].slice(0, rand(1..2)).each do |framework|
              add_framework_to_project(project: project, framework: framework)
            end
            print '.'
          end
          subgroup = FactoryBot.create(:group, parent: @group, name: "Subgroup #{suffix}",
            visibility_level: @group.visibility_level)
          (1..@projects_count_in_subgroup).each do |project_no|
            project = FactoryBot.create(:project, :repository, namespace: subgroup, creator: @admin,
              name: "#{FFaker::Product.product_name}-subgroup-#{project_no}", visibility_level: @group.visibility_level)
            @projects << project
            [red_framework, green_framework].slice(0, rand(1..2)).each do |framework|
              add_framework_to_project(project: project, framework: framework)
            end
            print '.'
          end
        end
      end
    end

    generate_compliance_violations

    puts "\nSuccessfully seeded '#{group.full_path}'\n"
    puts "URL: #{Rails.application.routes.url_helpers.group_url(group)}"
  end

  private

  def generate_compliance_violations
    puts "\n#################### Seeding compliance violations ####################"

    @projects.each do |project|
      control = project.project_control_compliance_statuses.first&.compliance_requirements_control
      next unless control

      # Use Gitlab::Audit::Auditor to create audit event properly
      ::Gitlab::Audit::Auditor.audit(
        name: 'project_name_updated',
        author: @admin,
        scope: project,
        target: project,
        message: "Seeded compliance violation for #{control.name}"
      )

      # Find the audit event we just created - use project_id to ensure correct match
      audit_event = AuditEvents::ProjectAuditEvent
        .where(project_id: project.id)
        .order(created_at: :desc)
        .first!

      violation = FactoryBot.create(:project_compliance_violation, namespace: project.namespace, project: project,
        audit_event_id: audit_event.id,
        audit_event_table_name: :project_audit_events,
        compliance_control: control,
        status: generate_violation_status
      )

      FactoryBot.create(:project_compliance_violation_issue, project: project, project_compliance_violation: violation)
    end
  end

  def add_framework_to_project(project:, framework:)
    project.compliance_management_frameworks << framework
    framework.compliance_requirements.each do |requirement|
      # only requirements with controls can generate entries
      next if requirement.compliance_requirements_controls.empty?

      status = determine_status
      create_requirement_compliance_status(project, requirement, status)
      create_control_compliance_statuses(project, requirement, status)
    end
  end

  def determine_status
    status_options = %w[pass pending fail]
    status_options.sample
  end

  def create_requirement_compliance_status(project, requirement, status)
    len = requirement.compliance_requirements_controls.length

    FactoryBot.create(
      :project_requirement_compliance_status,
      project: project,
      compliance_requirement: requirement,
      pending_count: status == 'pending' ? 1 : 0,
      fail_count: status == 'fail' ? 1 : 0,
      pass_count: status == 'pass' ? len : len - 1
    )
  end

  def create_control_compliance_statuses(project, requirement, status)
    failed_control_idx = rand(1..requirement.compliance_requirements_controls.length - 1)

    requirement.compliance_requirements_controls.each_with_index do |control, idx|
      FactoryBot.create(
        :project_control_compliance_status,
        project: project,
        compliance_requirement: requirement,
        compliance_requirements_control: control,
        status: (status == 'fail' || status == 'pending') && failed_control_idx == idx ? status : 'pass'
      )
    end
  end

  def create_group
    Sidekiq::Testing.inline! do
      namespace = FactoryBot.create(
        :group,
        :public,
        name: "Compliance Group #{suffix}",
        path: "p-compliance-group-#{suffix}"
      )

      namespace
    end
  end

  def create_compliance_framework(name, color:, with_requirements: false)
    framework = FactoryBot.create(
      :compliance_framework,
      namespace: @group,
      name: name,
      description: FFaker::Lorem.sentence,
      color: color
    )

    if with_requirements
      first_requirement = FactoryBot.create(
        :compliance_requirement,
        framework: framework,
        description: FFaker::Lorem.sentence,
        name: "1. #{FFaker::Lorem.word}"
      )

      %w[project_visibility_not_internal scanner_sast_running external].each do |control_name|
        trait = [control_name.to_sym]
        FactoryBot.create(
          :compliance_requirements_control,
          *trait,
          compliance_requirement: first_requirement
        )
      end

      second_requirement = FactoryBot.create(
        :compliance_requirement,
        framework: framework,
        name: "2. #{FFaker::Lorem.word}"
      )

      FactoryBot.create(
        :compliance_requirements_control,
        compliance_requirement: second_requirement
      )

      FactoryBot.create(
        :compliance_requirements_control,
        :external,
        compliance_requirement: second_requirement
      )

      FactoryBot.create(
        :compliance_requirement,
        name: "3. #{FFaker::Lorem.word} (no controls)",
        framework: framework,
        description: FFaker::Lorem.sentence
      )
    end

    framework
  end

  def suffix
    @suffix ||= Time.now.to_i
  end

  def generate_violation_status
    [:detected, :in_review, :resolved, :dismissed].sample
  end
end

Gitlab::Seeder.quiet do
  flag = 'SEED_COMPLIANCE_REPORT_DATA'
  group_id = ENV['GROUP_ID']

  group = Group.find(group_id) if group_id

  if ENV[flag]
    seeder = Gitlab::Seeder::ComplianceReportData.new(group)
    seeder.seed!
  else
    puts "Skipped seeding compliance frameworks and adherence report statuses."
    puts "Use the `#{flag}` environment variable to enable."
  end
end
