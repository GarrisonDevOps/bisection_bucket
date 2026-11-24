# frozen_string_literal: true

# Usage:
#
# Simple invocation always takes two existing groups
#
# FILTER=devops_adoption bundle exec rake db:seed_fu
#
# Run for a predefined existing group
#
# FILTER=devops_adoption DEVOPS_GROUP_ID=9 bundle exec rake db:seed_fu
class Gitlab::Seeder::DevopsAdoption # rubocop:disable Style/ClassAndModuleChildren
  attr_reader :groups

  def initialize(group: nil)
    @groups = [group] if group
    @groups ||= Group.not_mass_generated.order(:id).first(2)
  end

  def admin
    @admin ||= Gitlab::DatabaseImporters::AdminOrganizationImporter.seeded_admin
  end

  def seed!
    groups.each do |group|
      enabled_namespace = Analytics::DevopsAdoption::EnabledNamespace.find_or_initialize_by(namespace: group)

      if enabled_namespace.new_record?
        enabled_namespace.display_namespace = group
        enabled_namespace.save!
      end

      if enabled_namespace.invalid?
        puts "Error creating enabled_namespaces"
        puts enabled_namespaces.map(&:errors)
        next
      end

      # create snapshots for the last 5 months
      4.downto(0).each do |index|
        end_time = index.months.ago.at_end_of_month
        calculated_data = generate_calculated_data_for(enabled_namespace, end_time, index)

        snapshot = Analytics::DevopsAdoption::Snapshot.find_or_initialize_by(namespace_id: group.id, end_time: end_time)
        Analytics::DevopsAdoption::Snapshots::UpdateService.new(snapshot: snapshot, params: calculated_data).execute
      end

      puts "Successfully seeded '#{group.full_path}' for Devops adoption!"
      puts "URL: #{Rails.application.routes.url_helpers.group_url(group)}"
    end
  end

  # Derived from the snapshot index rather than rand, so a zero count and both boolean polarities
  # are always among the five snapshots a namespace gets.
  def generate_calculated_data_for(enabled_namespace, end_time, index)
    {
      namespace: enabled_namespace.namespace,
      issue_opened: index.even?,
      merge_request_opened: index.odd?,
      merge_request_approved: index.even?,
      runner_configured: index.odd?,
      pipeline_succeeded: index.even?,
      deploy_succeeded: index.odd?,
      code_owners_used_count: index,
      sast_enabled_count: index,
      dast_enabled_count: index,
      total_projects_count: index + 10,
      recorded_at: [end_time + 1.day, Time.zone.now].min,
      end_time: end_time
    }
  end
end

Gitlab::Seeder.quiet do
  group_id = ENV['DEVOPS_GROUP_ID']
  group = Group.find(group_id) if group_id

  Gitlab::Seeder::DevopsAdoption.new(group: group).seed!
end
