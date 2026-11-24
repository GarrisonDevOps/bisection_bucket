# frozen_string_literal: true

module Security
  class OrchestrationPolicyRuleScheduleWorker # rubocop:disable Scalability/IdempotentWorker
    include ApplicationWorker

    data_consistency :always
    # This worker does not perform work scoped to a context
    include CronjobQueue
    include Security::SecurityOrchestrationPolicies::CadenceChecker

    feature_category :security_policy_management

    def perform
      Security::OrchestrationPolicyRuleSchedule.with_configuration_and_project_or_namespace.with_owner.with_security_policy_bots.runnable_schedules.find_in_batches do |schedules|
        schedules.each do |schedule|
          with_context(project: schedule.security_orchestration_policy_configuration.project, user: schedule.owner) do
            config = schedule.security_orchestration_policy_configuration

            next unless security_policy_feature_available?(config)

            if config.project?
              schedule_rules(schedule)
            else
              Security::OrchestrationPolicyRuleScheduleNamespaceWorker.perform_async(schedule.id)
            end
          end
        end
      end
    end

    private

    def security_policy_feature_available?(config)
      return false unless config

      actor = config.project? ? config.project : config.namespace
      ::Security::PolicyAvailability.any_available?(actor)
    end

    def schedule_rules(schedule)
      project = schedule.security_orchestration_policy_configuration.project
      return if project.deletion_in_progress_or_scheduled_in_hierarchy_chain?

      user = project.security_policy_bot

      unless valid_cadence?(schedule.cron)
        log_invalid_cadence_error(project.id, schedule.cron)
        return
      end

      return prepare_security_policy_bot_user(project) unless user

      schedule.schedule_next_run!

      Security::ScanExecutionPolicies::RuleScheduleWorker.perform_async(project.id, user.id, schedule.id)
    end

    def prepare_security_policy_bot_user(project)
      Security::OrchestrationConfigurationCreateBotWorker.perform_async(project.id, nil)
    end
  end
end
