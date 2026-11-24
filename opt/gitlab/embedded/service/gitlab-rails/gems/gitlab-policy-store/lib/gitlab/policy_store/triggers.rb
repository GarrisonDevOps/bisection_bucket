# frozen_string_literal: true

module Gitlab
  module PolicyStore
    module Triggers
      # GOVERN-016's kinds. A `gate` trigger is asked before the change and may be
      # answered by stopping it; an `event` trigger is told after the fact and cannot
      # be. Nothing here enforces that pairing yet: kind is published so callers can
      # reason about it, and the save path learns to refuse a blocking action on an
      # event in https://gitlab.com/gitlab-org/gitlab/-/issues/631712. Its third kind,
      # `schedule`, has no authorable trigger yet.
      # https://gitlab.com/gitlab-org/architecture/govern/design-doc/-/merge_requests/28
      KIND_GATE = 'gate'
      KIND_EVENT = 'event'

      DEPLOYMENT_REQUESTED = 'deployment_requested'
      ENVIRONMENT_ADVANCED = 'environment_advanced'
      DEPLOYMENT_PROMOTED = 'deployment_promoted'
      PROJECT_SETTINGS_CHANGE_REQUESTED = 'project.before_settings_update'
      PROJECT_SETTINGS_DRIFT_CHECKED = 'project.scheduled_settings_drift_check'
      PROJECT_CREATED = 'project.after_create'
      PROJECT_TRANSFERRED = 'project.after_transfer'

      # TYPES is the persisted vocabulary, in Govern enum order, including the
      # internal ids the engine records on evaluations. ALL is the authoring
      # catalogue and stays a subset of TYPES: the drift check is recorded by the
      # engine on a schedule and is never authored, so it stays out of ALL.
      TYPES = [
        DEPLOYMENT_REQUESTED, ENVIRONMENT_ADVANCED, DEPLOYMENT_PROMOTED,
        PROJECT_SETTINGS_CHANGE_REQUESTED, PROJECT_SETTINGS_DRIFT_CHECKED,
        PROJECT_CREATED, PROJECT_TRANSFERRED
      ].freeze

      # Triggers whose context carries the project's group hierarchy. The engine looks
      # any other trigger up by organization alone, so a group's policy on it would run
      # against every group in the organization.
      NAMESPACE_SCOPED_TYPES = [
        PROJECT_SETTINGS_CHANGE_REQUESTED, PROJECT_SETTINGS_DRIFT_CHECKED,
        PROJECT_CREATED, PROJECT_TRANSFERRED
      ].freeze

      # Every persisted type and its kind. ALL offers a subset of these for
      # authoring, so a persisted-only type still has a kind to filter on.
      KIND_BY_TYPE = {
        DEPLOYMENT_REQUESTED => KIND_GATE,
        ENVIRONMENT_ADVANCED => KIND_GATE,
        DEPLOYMENT_PROMOTED => KIND_GATE,
        PROJECT_SETTINGS_CHANGE_REQUESTED => KIND_GATE,
        PROJECT_SETTINGS_DRIFT_CHECKED => KIND_EVENT,
        # Creation inherits some settings only after the project row exists, so there
        # is nothing left to gate by the time these fire.
        PROJECT_CREATED => KIND_EVENT,
        PROJECT_TRANSFERRED => KIND_EVENT
      }.freeze

      ALL = [
        { id: DEPLOYMENT_REQUESTED, name: 'Deployment requested', kind: KIND_BY_TYPE[DEPLOYMENT_REQUESTED] }.freeze,
        { id: ENVIRONMENT_ADVANCED, name: 'Environment advanced', kind: KIND_BY_TYPE[ENVIRONMENT_ADVANCED] }.freeze,
        { id: DEPLOYMENT_PROMOTED, name: 'Deployment promoted', kind: KIND_BY_TYPE[DEPLOYMENT_PROMOTED] }.freeze,
        { id: PROJECT_SETTINGS_CHANGE_REQUESTED, name: 'Project settings change requested',
          kind: KIND_BY_TYPE[PROJECT_SETTINGS_CHANGE_REQUESTED] }.freeze,
        { id: PROJECT_CREATED, name: 'Project created', kind: KIND_BY_TYPE[PROJECT_CREATED] }.freeze,
        { id: PROJECT_TRANSFERRED, name: 'Project transferred', kind: KIND_BY_TYPE[PROJECT_TRANSFERRED] }.freeze
      ].freeze

      def self.gate?(type)
        KIND_BY_TYPE[type] == KIND_GATE
      end
    end
  end
end
