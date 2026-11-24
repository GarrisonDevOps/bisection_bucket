# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class RuleScheduleService < BaseProjectService
      def execute(schedule)
        return ServiceResponse.error(message: "No rules") unless rules = schedule&.policy&.fetch(:rules, nil)

        rule = rules[schedule.rule_index]

        return ServiceResponse.error(message: "No scheduled rules") unless schedule_rule?(rule)

        branches = branches_for(rule)
        actions = actions_for(schedule)

        schedule_scans_using_a_worker(branches, schedule) unless actions.blank?

        ServiceResponse.success
      end

      private

      def schedule_rule?(rule)
        rule.present? && rule[:type] == Security::ScanExecutionPolicy::RULE_TYPES[:schedule]
      end

      def actions_for(schedule)
        policy = schedule.policy
        return [] if policy.blank?

        policy[:actions]
      end

      def branches_for(rule)
        ::Security::SecurityOrchestrationPolicies::PolicyBranchesService
          .new(project: project)
          .scan_execution_branches([rule])
      end

      def schedule_scans_using_a_worker(branches, schedule)
        if Feature.enabled?(:scan_execution_policy_project_schedule_creation, project)
          create_project_schedule_if_not_exists(schedule)
        end

        return if Feature.enabled?(:scan_execution_policy_per_project_scheduling, project)

        enqueue_pipelines(branches, schedule)
      end

      def create_project_schedule_if_not_exists(schedule)
        security_policy = find_security_policy(schedule)

        unless security_policy
          log_missing_security_policy(schedule)
          return
        end

        capped_time_window = schedule.effective_time_window(nil, defer_cap: true)
        delay = capped_time_window&.positive? ? Random.rand(capped_time_window) : 0

        created = Security::ScanExecutionProjectSchedule.create_if_not_exists(
          policy_rule_schedule: schedule,
          project: project,
          security_policy: security_policy,
          next_run_at: schedule.next_run_at + delay.seconds,
          next_run_applied_delay: delay
        )

        log_project_schedule_created(schedule, security_policy) if created
      end

      def log_project_schedule_created(schedule, security_policy)
        Gitlab::AppJsonLogger.info(
          message: 'ScanExecutionProjectSchedule created via self-healing',
          project_id: project.id,
          rule_schedule_id: schedule.id,
          security_policy_id: security_policy.id
        )
      end

      def find_security_policy(schedule)
        Security::Policy.for_rule_schedule(schedule).first
      end

      def log_missing_security_policy(schedule)
        Gitlab::AppJsonLogger.warn(
          message: 'Security::Policy record not found for rule schedule, skipping project schedule creation',
          project_id: project.id,
          rule_schedule_id: schedule.id,
          policy_index: schedule.policy_index,
          security_orchestration_policy_configuration_id:
            schedule.security_orchestration_policy_configuration_id
        )
      end

      def enqueue_pipelines(branches, schedule)
        capped_time_window = schedule.effective_time_window

        if capped_time_window&.positive?
          branches.map do |branch|
            ::Security::ScanExecutionPolicies::CreatePipelineWorker.perform_in(Random.rand(capped_time_window).seconds,
              project.id,
              current_user.id,
              schedule.id,
              branch)
          end
        else
          branches.map do |branch|
            ::Security::ScanExecutionPolicies::CreatePipelineWorker.perform_async(project.id,
              current_user.id,
              schedule.id,
              branch)
          end
        end
      end
    end
  end
end
