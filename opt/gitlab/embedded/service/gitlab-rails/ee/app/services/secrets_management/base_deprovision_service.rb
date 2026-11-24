# frozen_string_literal: true

module SecretsManagement
  # Shared async-deprovision logic for both project and group secrets
  # managers. This is what the worker calls.
  #
  # The OpenBao paths we need to tear down (organization, root namespace,
  # the entity itself) are read off the maintenance task, NOT off the
  # secrets manager record. That's deliberate: by the time this runs, the
  # parent project or group may already be destroyed. The maintenance
  # task carries a snapshot of the IDs we need, taken at the moment the
  # destroy/transfer hook fired, so paths stay correct regardless of
  # what's happened to the live records in between.
  #
  # The SM row is typically already gone by the time this worker runs.
  # Either `InitiateDeprovisionService` destroyed it inline before
  # enqueuing this job, or the parent project/group was destroyed and
  # CASCADE deleted it. The maintenance task carries the snapshot ids
  # the worker needs; the orphan signal lives in the task table now,
  # not on the SM row. Stuck tasks (exhausted `MAX_RETRIES`) get picked
  # up by the reaper cron (gitlab-org/gitlab#600120).
  #
  # End state when everything succeeds:
  #   - OpenBao namespaces removed (entity -> root group -> org)
  #   - Secrets manager row destroyed
  #   - Maintenance task destroyed
  #
  # Subclasses (project / group versions) must implement:
  #   - lease_key_prefix     scope-specific lease key namespace
  #   - entity_path          the level-3 path (project_<id> or group_<id>)
  #   - find_secrets_manager best-effort lookup; may return nil
  #   - payload_key          key for the ServiceResponse payload
  class BaseDeprovisionService
    include Gitlab::ExclusiveLeaseHelpers
    include Helpers::ExclusiveLeaseHelper
    include Helpers::ErrorResponseHelper

    LEASE_TIMEOUT = 120.seconds.to_i
    MAX_NAMESPACE_STATUS_POLL_ATTEMPTS = 20
    POLL_SLEEP_INTERVAL = 0.1.seconds

    attr_reader :maintenance_task, :current_user

    def initialize(maintenance_task, current_user)
      @maintenance_task = maintenance_task
      @current_user = current_user
    end

    def execute
      in_lock(lease_key, ttl: LEASE_TIMEOUT, retries: 0) do
        execute_deprovision
      end
    rescue FailedToObtainLockError
      obtain_lease_failure_response
    end

    private

    delegate :org_path, :root_namespace_path, to: :maintenance_task

    def lease_key
      "#{lease_key_prefix}:#{entity_path}"
    end

    # Subclasses override these.
    def lease_key_prefix
      raise NotImplementedError
    end

    def entity_path
      raise NotImplementedError
    end

    def find_secrets_manager
      raise NotImplementedError
    end

    def payload_key
      raise NotImplementedError
    end

    # Async deprovision may run after the project/group is gone; use the
    # system JWT so we don't depend on a live parent record.
    def base_secrets_manager_client
      @base_secrets_manager_client ||= begin
        jwt = GlobalSecretsManagerJwt.new(current_user: current_user).encoded
        SecretsManagerClient.new(jwt: jwt)
      end
    end

    def org_secrets_manager_client
      @org_secrets_manager_client ||=
        base_secrets_manager_client.with_namespace(org_path)
    end

    def namespace_secrets_manager_client
      @namespace_secrets_manager_client ||=
        base_secrets_manager_client.with_namespace([org_path, root_namespace_path].join('/'))
    end

    def execute_deprovision
      disable_entity_namespace
      disable_root_namespace
      disable_org_namespace

      # The DB cleanup runs in a single transaction so "deprovision is
      # complete" is an atomic fact at the row level. If either delete
      # fails, both roll back and the next worker run (or the reaper)
      # picks up the consistent state.
      #
      # Order inside the transaction: task first, then secrets manager.
      # The SM is typically already gone when this runs (CASCADE from
      # parent destroy, or destroyed inline by `InitiateDeprovisionService`
      # before this worker was enqueued), so `delete_secrets_manager`
      # is usually a no-op. Tearing down the task explicitly keeps the
      # flow correct in the edge case where the SM row survived.
      ApplicationRecord.transaction do
        delete_maintenance_task
        delete_secrets_manager
      end

      ServiceResponse.success(payload: { payload_key => maintenance_task })
    end

    # Deleting the entity namespace also removes all data under it
    # (auth engines, secrets engine, policies). Namespaces can only be
    # disabled when empty of children; the entity namespace has none.
    def disable_entity_namespace
      MAX_NAMESPACE_STATUS_POLL_ATTEMPTS.times do |n|
        result = namespace_secrets_manager_client.disable_namespace(entity_path, allow_missing: true)
        if result.key?("data") && !result["data"].nil? &&
            result["data"].key?("status") && !result["data"]["status"].nil? &&
            result["data"]["status"] == "in-progress"
          sleep POLL_SLEEP_INTERVAL * n
          next
        end

        break
      end
    rescue SecretsManagement::SecretsManagerClient::ApiError => e
      # Namespace was never created (e.g. legacy record); continue cleanup.
      raise e unless e.message.include? SecretsManagerClient::NAMESPACE_NOT_FOUND_MESSAGE
    end

    # Lazily delete the root group (level 2) namespace. The level-2 and
    # level-1 parents are shared by every SM under them, so each worker
    # speculatively tries to delete them and tolerates two outcomes:
    #
    #   - "containing child namespaces": at least one sibling SM is
    #     still alive under this parent, so we leave the cleanup for
    #     whichever sibling runs last.
    #
    #   - "route entry not found": another worker beat us to the
    #     delete. Concretely, picture a group transfer that initiates
    #     deprovision for N SMs at once. Worker A finishes its entity
    #     teardown first, finds the parent empty, deletes it. Worker B
    #     finishes its entity teardown a moment later, also tries to
    #     delete the parent, but OpenBao reports the namespace is gone
    #     because A already deleted it. From B's point of view that is
    #     not an error: the desired end state is "parent removed", and
    #     it already happened.
    #
    # Failing to rescue either of these would leak the exception up to
    # the worker, mark the maintenance task as failed, and leave it
    # stuck on the retry path. The cron retry worker would just hit the
    # same outcome on every run, never letting the task drain.
    def disable_root_namespace
      org_secrets_manager_client.disable_namespace(root_namespace_path, allow_missing: true, allow_children: true)
    rescue SecretsManagement::SecretsManagerClient::ApiError => e
      raise e unless lazy_cleanup_expected_error?(e)
    end

    # Lazily delete the organization (level 1) namespace. Same two
    # expected outcomes as `disable_root_namespace`.
    def disable_org_namespace
      base_secrets_manager_client.disable_namespace(org_path, allow_missing: true, allow_children: true)
    rescue SecretsManagement::SecretsManagerClient::ApiError => e
      raise e unless lazy_cleanup_expected_error?(e)
    end

    def lazy_cleanup_expected_error?(error)
      error.message.include?(SecretsManagerClient::NAMESPACE_HAS_CHILDREN_MESSAGE) ||
        error.message.include?(SecretsManagerClient::NAMESPACE_NOT_FOUND_MESSAGE)
    end

    # In the trigger-driven world (gitlab-org/gitlab#600290), the SM row
    # is normally already gone by the time this worker runs: either
    # `InitiateDeprovisionService` destroyed it inline before enqueueing
    # this job, or CASCADE deleted it when the parent project/group was
    # destroyed. Either way the trigger inserted the maintenance task we
    # are draining. `find_secrets_manager` should therefore return nil
    # and `&.destroy!` no-ops. We keep the call as a safety net for the
    # rare edge case where an SM row somehow survived an earlier partial
    # run; destroying it here would not re-fire the trigger meaningfully
    # because the task already exists and `ON CONFLICT (parent_id) DO
    # NOTHING` would skip the dup INSERT.
    def delete_secrets_manager
      find_secrets_manager&.destroy!
    end

    # Destroy the maintenance task explicitly so the deprovision flow
    # doesn't depend on any FK CASCADE behavior between the task and
    # the secrets manager. That keeps us aligned with the no-CASCADE
    # policy described in gitlab-org/gitlab#600120.
    def delete_maintenance_task
      maintenance_task.destroy!
    end
  end
end
