# frozen_string_literal: true

module Cd
  class Application < ApplicationRecord
    include Gitlab::SQL::Pattern

    self.table_name = 'cd_applications'

    belongs_to :organization, class_name: '::Organizations::Organization', optional: false
    has_many :services, class_name: 'Cd::Service', inverse_of: :application
    has_many :version_sets, class_name: 'Cd::VersionSet', inverse_of: :application
    has_many :rollouts, class_name: 'Cd::Rollout', inverse_of: :application
    has_many :application_flow_definitions, -> { ordered },
      class_name: 'Cd::ApplicationFlowDefinition', inverse_of: :application
    has_many :application_links, class_name: 'Cd::ApplicationLink', inverse_of: :application

    validates :name, presence: true, length: { maximum: 255 }, uniqueness: { scope: :organization_id },
      format: { with: Gitlab::Regex.cd_name_regex, message: Gitlab::Regex.cd_name_regex_message }
    validates :description, length: { maximum: 2000 }

    scope :for_organization, ->(organization_id) { where(organization_id: organization_id) }
    scope :in_organization, ->(organization) { where(organization_id: organization) }
    scope :search, ->(query) { fuzzy_search(query, [:name, :description]) }

    scope :with_worst_health, ->(healths, organization:) {
      where(id: ::Cd::ServiceEnvironmentHealth.application_ids_with_worst_health(healths, organization: organization))
    }

    scope :deploying, ->(organization:) {
      where(id: ::Cd::Rollout.in_progress.in_organization(organization).select(:application_id))
    }

    scope :with_status, ->(status, organization:) {
      case status
      when 'healthy', 'degraded' then with_worst_health(status, organization: organization)
      when 'deploying' then deploying(organization: organization)
      # awaiting_approval has no backend yet, so it matches nothing.
      else none
      end
    }

    # Caps how many of the application's most recent rollouts are considered
    # by #environments, #deployments, and #last_deployed_at below. An
    # application's rollout history only grows over time, so deriving these
    # from the full history would make the underlying queries scan an
    # unbounded, ever-increasing number of rows. If a complete (unbounded)
    # view is needed later, back it with a dedicated read-optimised table
    # instead of raising this limit further.
    RECENT_ROLLOUTS_LIMIT = 100

    # Single most-urgent status for each of the given applications, keyed by
    # id, derived from the same signals as `.with_status` (worst service
    # health rollup, then an active rollout) collapsed to one value per
    # application: 'degraded' outranks 'deploying', which outranks 'healthy'.
    # Applications with no reported health (or a 'failed'/'unknown' rollup)
    # and no rollout in progress are omitted, so callers can distinguish "no
    # status" from an observed one.
    def self.statuses_by_id(application_ids)
      healths = ::Cd::ServiceEnvironmentHealth.for_application(application_ids).worst_per_application
        .to_h { |health| [health.application_id, health.health] }
      # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- bounded to the given application_ids
      deploying_ids = ::Cd::Rollout.in_progress.where(application_id: application_ids).distinct.pluck(:application_id)
      # rubocop:enable Database/AvoidUsingPluckWithoutLimit

      application_ids.index_with do |id|
        next 'degraded' if healths[id] == 'degraded'
        next 'deploying' if deploying_ids.include?(id)
        next 'healthy' if healths[id] == 'healthy'
      end.compact
    end

    # Distinct environments this application has rolled out to, considering
    # only its RECENT_ROLLOUTS_LIMIT most recent rollouts. There is no direct
    # Application-Environment association (environments belong to the
    # organization and are shared across applications), so this is derived
    # from the application's rollout history.
    def environments
      ::Cd::Environment
        .joins(rollout_environments: :rollout)
        .merge(::Cd::Rollout.where(id: recent_rollout_ids))
        .distinct
    end

    # Deployments (of any service, to any environment) actuated by this
    # application's RECENT_ROLLOUTS_LIMIT most recent rollouts. There is no
    # direct Application-Deployment association, so this is derived via the
    # rollout -> rollout_environment -> deployment chain.
    def deployments
      ::Cd::Deployment
        .joins(rollout_environment: :rollout)
        .merge(::Cd::Rollout.where(id: recent_rollout_ids))
    end

    # Timestamp of the application's most recently finished deployment among
    # its RECENT_ROLLOUTS_LIMIT most recent rollouts, or nil if none of them
    # have a finished deployment yet.
    def last_deployed_at
      deployments.maximum(:finished_at)
    end

    def next_rollout_iid!
      with_lock do
        increment!(:last_rollout_iid)
        last_rollout_iid
      end
    end

    private

    def recent_rollout_ids
      rollouts.order(id: :desc).limit(RECENT_ROLLOUTS_LIMIT).select(:id)
    end
  end
end
