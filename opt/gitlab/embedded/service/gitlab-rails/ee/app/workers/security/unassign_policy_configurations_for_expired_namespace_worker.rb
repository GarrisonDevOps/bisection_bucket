# frozen_string_literal: true

module Security
  class UnassignPolicyConfigurationsForExpiredNamespaceWorker
    include ApplicationWorker

    feature_category :security_policy_management
    data_consistency :sticky
    deduplicate :until_executed
    idempotent!

    BATCH_SIZE = 100

    def perform(namespace_id)
      # Policy configurations only ever hang off groups; self_and_descendants_ids is Group-only.
      namespace = Group.find_by_id(namespace_id)
      return unless namespace

      log_start(namespace_id)

      namespace_ids = namespace.self_and_descendants_ids
      project_ids = namespace.all_project_ids

      configurations_count = 0

      policy_configurations(namespace_ids, project_ids).find_each(batch_size: BATCH_SIZE) do |configuration| # rubocop:disable CodeReuse/ActiveRecord -- the logic is specific to this service
        container = configuration.source
        admin_bot = admin_bot_for_container_organization(container)

        Security::Orchestration::UnassignService
          .new(container: container, current_user: admin_bot)
          .execute(delete_bot: true, skip_csp: false)

        configurations_count += 1
      end

      log_end(namespace_id, configurations_count)
    end

    private

    def policy_configurations(namespace_ids, project_ids)
      Security::OrchestrationPolicyConfiguration
        .for_namespace_and_projects(namespace_ids, project_ids)
    end

    def admin_bot_for_container_organization(container)
      @admin_bots ||= {}
      @admin_bots[container.organization_id] ||= Users::Internal.in_organization(container.organization_id).admin_bot
    end

    def log_start(namespace_id)
      ::Gitlab::AppJsonLogger.info(
        class: self.class.name,
        message: "Starting policy configurations unassignment for expired namespace subscription",
        namespace_id: namespace_id
      )
    end

    def log_end(namespace_id, configurations_count)
      ::Gitlab::AppJsonLogger.info(
        class: self.class.name,
        message: "Completed policy configurations unassignment for expired namespace subscription",
        namespace_id: namespace_id,
        configurations_count: configurations_count
      )
    end
  end
end
