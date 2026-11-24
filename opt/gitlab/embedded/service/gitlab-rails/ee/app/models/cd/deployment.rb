# frozen_string_literal: true

module Cd
  class Deployment < ApplicationRecord
    self.table_name = 'cd_deployments'

    TERMINAL_STATES = %i[healthy degraded failed cancelled].freeze

    belongs_to :service, class_name: 'Cd::Service', optional: false
    belongs_to :rollout_environment, class_name: 'Cd::RolloutEnvironment', inverse_of: :deployments,
      optional: false
    belongs_to :organization, class_name: '::Organizations::Organization', optional: false
    has_many :deployment_transitions, -> { ordered },
      class_name: 'Cd::DeploymentTransition', inverse_of: :deployment

    populate_sharding_key :organization_id, source: :service

    scope :for_service, ->(service) { where(service: service) }

    validates :service_id, uniqueness: { scope: :rollout_environment_id,
                                         message: ->(*) { _('already has a deployment in this rollout environment') } }

    # State machine defining the deployment lifecycle.
    # See https://gitlab.com/groups/gitlab-org/-/work_items/21247#deployment-states-per-service-within-a-rollout
    state_machine :state, initial: :pending do
      # -- Forward flow --
      event :start_deploying do
        transition pending: :deploying
      end

      event :mark_healthy do
        transition deploying: :healthy
      end

      event :mark_degraded do
        transition deploying: :degraded
      end

      # Named `fail_deployment` to avoid conflict with Ruby's `Kernel#fail`.
      event :fail_deployment do
        transition deploying: :failed
      end

      # -- Cancellation --
      event :cancel do
        transition deploying: :cancelled
      end

      # -- Callbacks --
      before_transition any => :deploying do |deployment|
        deployment.started_at ||= Time.current
      end

      before_transition any => TERMINAL_STATES do |deployment|
        deployment.finished_at = Time.current
      end

      # Stopgap: applications don't report health yet, so a finished deployment
      # records it. Remove once real health reporting lands.
      after_transition any => [:healthy, :degraded] do |deployment|
        ::Cd::ServiceEnvironmentHealth.record_deployment!(deployment)
      end

      # after_transition never fires on creation, so a newly inserted pending
      # deployment leaves the parent's state untouched.
      #
      # TODO: journal each state change here once the workflow-event path drives
      # transitions with a principal: https://gitlab.com/gitlab-org/gitlab/-/work_items/607142
      after_transition any => any do |deployment|
        deployment.reload_rollout_environment.sync_state_from_deployments!
      end

      # BulkInsertSafe forbids after_commit, so use after_all_transactions_commit
      # (like Cd::RolloutStep).
      after_transition any => TERMINAL_STATES do |deployment|
        ActiveRecord.after_all_transactions_commit do
          GraphqlTriggers.cd_service_updated(deployment.service)
          GraphqlTriggers.cd_environment_service_updated(deployment)
        end
      end

      after_transition any => any do |deployment|
        ActiveRecord.after_all_transactions_commit do
          GraphqlTriggers.cd_deployment_updated(deployment)
        end
      end
    end

    enum :state, {
      pending: 0,
      deploying: 1,
      healthy: 2,
      degraded: 3,
      failed: 4,
      cancelled: 5
    }

    # Timestamp of the most recently finished deployment for each of the
    # given services, keyed by service id. Services with no finished
    # deployment (nothing yet in a TERMINAL_STATES) are omitted, so the
    # caller can distinguish "no deployment yet" (absent) from any actual
    # timestamp.
    #
    # Batched (rather than exposed as a per-service instance method) so
    # callers rendering a list of services (for example, the services panel
    # on the application overview page) can resolve this in a single query
    # instead of once per service.
    def self.last_deployed_at_by_service(service_ids)
      where(service_id: service_ids)
        .where.not(finished_at: nil)
        .group(:service_id)
        .maximum(:finished_at)
    end

    # Included at the bottom of the model definition because BulkInsertSafe
    # complains about the autosave callbacks generated for the `has_many`
    # associations otherwise.
    include BulkInsertSafe
  end
end
