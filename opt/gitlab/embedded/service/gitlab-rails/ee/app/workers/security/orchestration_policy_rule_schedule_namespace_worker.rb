# frozen_string_literal: true

module Security
  class OrchestrationPolicyRuleScheduleNamespaceWorker
    BATCH_SIZE = 50
    BATCH_DELAY = 5
    # Delays wrap inside this window so jobs start within it, below the 15-minute cron interval.
    SPREAD_WINDOW = 14.minutes.to_i
    include ApplicationWorker
    include Security::SecurityOrchestrationPolicies::CadenceChecker

    feature_category :security_policy_management

    data_consistency :sticky

    idempotent!

    def perform(rule_schedule_id)
      schedule = Security::OrchestrationPolicyRuleSchedule.find_by_id(rule_schedule_id)
      return unless schedule

      security_orchestration_policy_configuration = schedule.security_orchestration_policy_configuration
      return unless should_run?(security_orchestration_policy_configuration, schedule)

      namespace = security_orchestration_policy_configuration.namespace

      unless valid_cadence?(schedule.cron)
        log_invalid_cadence_error(namespace.id, schedule.cron)
        return
      end

      schedule.schedule_next_run!

      batch_index = 0
      projects_in_batches(security_orchestration_policy_configuration) do |projects|
        bots_by_project_id = security_policy_bot_ids_by_project_ids(projects)
        ready_projects, missing_bot_projects = projects.partition { |project| bots_by_project_id[project.id] }
        missing_bot_projects.each { |project| prepare_security_policy_bot_user(project) }

        enqueue_rule_schedule_workers(ready_projects, bots_by_project_id, schedule, batch_index)
        batch_index += 1
      end
    end

    private

    def enqueue_rule_schedule_workers(projects, bots_by_project_id, schedule, batch_index)
      return if projects.empty?

      arguments_proc = ->(project) { [project.id, bots_by_project_id[project.id], schedule.id] }
      context_proc = ->(project) { { project: project } }

      Security::ScanExecutionPolicies::RuleScheduleWorker.bulk_perform_in_with_contexts(
        batch_delay(batch_index), projects, arguments_proc: arguments_proc, context_proc: context_proc)
    end

    def batch_delay(batch_index)
      ((batch_index * BATCH_DELAY) % SPREAD_WINDOW) + BATCH_DELAY
    end

    def should_run?(security_orchestration_policy_configuration, schedule)
      namespace_configuration?(security_orchestration_policy_configuration) && schedule_in_the_past?(schedule)
    end

    def namespace_configuration?(security_orchestration_policy_configuration)
      security_orchestration_policy_configuration.namespace? && security_orchestration_policy_configuration.namespace.present?
    end

    def schedule_in_the_past?(schedule)
      schedule.next_run_at.past?
    end

    def prepare_security_policy_bot_user(project)
      Security::OrchestrationConfigurationCreateBotWorker.perform_async(project.id, nil)
    end

    def security_policy_bot_ids_by_project_ids(projects)
      User.security_policy_bots_for_projects(projects).select(:id, :source_id).to_h do |bot|
        [bot.source_id, bot.id]
      end
    end

    def projects_in_batches(configuration, &block)
      configuration
        .namespace
        .all_projects_with_csp_in_batches(of: BATCH_SIZE, only_active: true, &block)
    end

    def log_invalid_cadence_error(namespace_id, cadence)
      Gitlab::AppJsonLogger.info(event: 'scheduled_scan_execution_policy_validation',
        message: 'Invalid cadence',
        namespace_id: namespace_id,
        cadence: cadence)
    end
  end
end
