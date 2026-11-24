# frozen_string_literal: true

# Seeds ai_flow_schedules so migrations touching the table are exercised by
# db:migrate:multi-version-upgrade (tables without seed data are never covered).
class Gitlab::Seeder::AiFlowSchedules # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  def seed!
    if Ai::FlowSchedule.exists?
      print '.'
      return
    end

    project = Project.not_mass_generated.first
    return warn "\nSkipping ai_flow_schedules seeds: no project available" unless project

    FactoryBot.create(
      :ai_flow_schedule,
      flow_trigger: create_trigger(project),
      description: 'Seeded weekly flow schedule'
    )
    print '.'
  end

  private

  def create_trigger(project)
    service_account = FactoryBot.create(
      :user,
      :service_account,
      username: "flow_schedule_sa_#{SecureRandom.hex(4)}",
      organization: project.organization
    )

    # Scheduled automations are gated behind the beta setting, off by default in a
    # fresh GDK.
    Gitlab::CurrentSettings.current_application_settings
      .update!(instance_level_ai_beta_features_enabled: true)

    FactoryBot.create(
      :ai_flow_trigger,
      project: project,
      user: service_account,
      event_types: [Ai::FlowTrigger::EVENT_TYPES[:scheduled]],
      description: 'Seeded scheduled flow trigger'
    )
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating ai_flow_schedules"

  Gitlab::Seeder::AiFlowSchedules.new.seed!
rescue StandardError => e
  warn "\nError seeding ai_flow_schedules: #{e}"
end
