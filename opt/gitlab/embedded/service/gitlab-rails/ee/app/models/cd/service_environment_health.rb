# frozen_string_literal: true

module Cd
  class ServiceEnvironmentHealth < ApplicationRecord
    self.table_name = 'cd_service_environment_healths'

    belongs_to :service, class_name: 'Cd::Service', inverse_of: :service_environment_healths, optional: false
    belongs_to :environment, class_name: 'Cd::Environment', inverse_of: :service_environment_healths, optional: false
    belongs_to :organization, class_name: '::Organizations::Organization', optional: false

    populate_sharding_key :organization_id, source: :service

    validates :environment_id, uniqueness: { scope: :service_id }
    validates :observed_at, presence: true

    enum :health, {
      unknown: 0,
      healthy: 1,
      degraded: 2,
      failed: 3
    }

    # Worst-to-best severity order. Any degraded/failed signal takes
    # precedence over a healthy one, so problems are never hidden behind a
    # healthy result elsewhere.
    HEALTH_SEVERITY_ORDER = %w[failed degraded healthy unknown].freeze

    scope :in_organization, ->(organization) { where(organization_id: organization) }
    scope :for_environment, ->(environment) { where(environment_id: environment) }
    scope :for_application, ->(application) { joins(:service).where(cd_services: { application_id: application }) }

    # Orders records from worst to best health, per HEALTH_SEVERITY_ORDER. A
    # health value not present in HEALTH_SEVERITY_ORDER (for example, if this
    # enum gains a new value in the future) sorts after all known values,
    # since array_position returns NULL for it and we order nulls last below.
    #
    # Uses a Gitlab::Pagination::Keyset::Order (rather than a plain `order`)
    # because this scope backs the serviceEnvironmentHealths GraphQL
    # connection, which uses keyset pagination; a raw computed expression
    # like array_position can't be paginated without describing it this way.
    # `id` is included as a tiebreaker so the order is fully deterministic.
    scope :ordered_by_severity, -> {
      severity_rank = Arel::Nodes::NamedFunction.new(
        'array_position', [Arel.sql(severity_array_sql), arel_table[:health]]
      )

      keyset_order = Gitlab::Pagination::Keyset::Order.build([
        Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
          attribute_name: 'severity_rank',
          order_expression: severity_rank.asc,
          nullable: :nulls_last,
          add_to_projections: true
        ),
        Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
          attribute_name: 'id',
          order_expression: arel_table[:id].asc,
          nullable: :not_nullable
        )
      ])

      reorder(keyset_order)
    }

    # Worst (most severe) health record per environment, per
    # HEALTH_SEVERITY_ORDER. Environments with no reported health are absent,
    # so callers can distinguish "no signal yet" from an observed `unknown`.
    scope :worst_per_environment, -> {
      select("DISTINCT ON (environment_id) #{table_name}.*")
        .order(Arel.sql("environment_id, array_position(#{severity_array_sql}, health), id"))
    }

    # Application counterpart of worst_per_environment. The application is
    # reached through cd_services, so the row carries an application_id
    # attribute projected from the join.
    scope :worst_per_application, -> {
      select("DISTINCT ON (cd_services.application_id) #{table_name}.*, " \
        "cd_services.application_id AS application_id")
        .joins(:service)
        .order(Arel.sql(
          "cd_services.application_id, array_position(#{severity_array_sql}, #{table_name}.health), #{table_name}.id"
        ))
    }

    # The health filter must wrap the DISTINCT ON subquery: filtering inside
    # it would change which row wins per environment.
    def self.environment_ids_with_worst_health(healths, organization:)
      worst = in_organization(organization).worst_per_environment

      from(worst, table_name).where(health: healths).select(:environment_id)
    end

    def self.application_ids_with_worst_health(healths, organization:)
      worst = in_organization(organization).worst_per_application

      from(worst, table_name).where(health: healths).select(:application_id)
    end

    # Distinct applications with services in each environment, keyed by environment
    # id. Derived from the live per-service inventory (cd_service_environment_healths).
    def self.applications_count_by_environment(environment_ids)
      joins(:service)
        .where(environment_id: environment_ids)
        .group('cd_service_environment_healths.environment_id')
        .distinct
        .count('cd_services.application_id')
    end

    # Service health rows in the environment grouped by application, keyed by
    # application id and ordered by application name then service name. The
    # service, application, and organization are preloaded so grouping and
    # authorizing each row (ServicePolicy delegates to application, then
    # organization) add no queries.
    def self.service_environment_healths_by_application(environment)
      joins(service: :application)
        .where(environment_id: environment.id)
        .order('cd_applications.name ASC', 'cd_services.name ASC')
        .preload(service: { application: :organization })
        .group_by { |health| health.service.application_id }
    end

    # Services in each environment, keyed by environment id. The table is unique on
    # (service_id, environment_id), so a grouped count is already the distinct service
    # count -- no join or DISTINCT needed (unlike applications_count_by_environment).
    def self.services_count_by_environment(environment_ids)
      where(environment_id: environment_ids)
        .group(:environment_id)
        .count
    end

    # Stopgap until deployed applications report health themselves: a finished
    # deployment stands in for an observation so the service shows up in its
    # environment right away. Real reports will overwrite this row (last write
    # wins), and this method goes away once they exist.
    def self.record_deployment!(deployment)
      upsert(
        {
          service_id: deployment.service_id,
          environment_id: deployment.rollout_environment.environment_id,
          organization_id: deployment.organization_id,
          health: healths.fetch(deployment.state),
          observed_at: deployment.finished_at
        },
        unique_by: [:service_id, :environment_id]
      )
    end

    def self.severity_array_sql
      "ARRAY[#{healths.values_at(*HEALTH_SEVERITY_ORDER).join(',')}]"
    end

    # Environment ids where any of the application's services has reported
    # health. An id subquery, so an environment with several of the app's
    # services appears once without a DISTINCT that breaks keyset pagination.
    def self.environment_ids_for_application(application_id)
      where(service_id: ::Cd::Service.where(application_id: application_id).select(:id))
        .select(:environment_id)
    end
  end
end
