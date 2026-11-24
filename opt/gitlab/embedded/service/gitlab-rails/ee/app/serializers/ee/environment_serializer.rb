# frozen_string_literal: true

module EE
  module EnvironmentSerializer
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    override :environment_associations
    def environment_associations
      super.deep_merge(latest_opened_most_severe_alert: [])
    end

    override :deployment_associations
    def deployment_associations
      super.deep_merge(approvals: {
        user: []
      })
    end

    override :project_associations
    def project_associations
      super.deep_merge(protected_environments: [])
    end

    override :batch_load
    def batch_load(resource)
      environments = super

      ::Preloaders::Environments::ProtectedEnvironmentPreloader.new(environments).execute(association_attributes)

      environments.each do |environment|
        # Ci::JobEntity evaluates :cancel_build / :retry_job / :play_job per
        # build; the EE DeployablePolicy condition reads
        # `persisted_environment.protected_from?(user)`. Seeding the already
        # loaded environment skips a per-build env-by-name lookup that also
        # reloads the project.
        [environment.last_deployment, environment.upcoming_deployment].each do |deployment|
          deployable = deployment&.deployable
          next unless deployable

          deployable.persisted_environment = environment

          pipeline = deployable.pipeline
          next unless pipeline

          actions = pipeline.manual_actions + pipeline.scheduled_actions
          actions.each do |action|
            next unless action.expanded_environment_name == environment.name

            action.persisted_environment = environment
          end
        end
      end
    end

    def association_attributes
      [:deploy_access_levels, :project, { approval_rules: [:user, :group] }]
    end
  end
end
