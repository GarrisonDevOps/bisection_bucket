# frozen_string_literal: true

module Ml
  class DestroyModelService
    include Gitlab::Utils::StrongMemoize

    VERSIONS_BATCH_SIZE = 1_000

    def initialize(model, user)
      @model = model
      @user = user
    end

    def execute
      return error if batched_deletion? && !prepare_experiment_deletion

      package_deletion_result = ::Packages::MarkPackagesForDestructionService.new(
        packages: @model.all_packages,
        current_user: @user
      ).execute

      return packages_not_deleted(package_deletion_result.message) if package_deletion_result.error?

      package_ids = @model.package_ids

      return error unless destroy_model

      audit_destroy_event(@model)
      ::Packages::MlModel::DestroyOrphanedPackagesService.new(package_ids).execute if package_ids.any?

      success
    end

    private

    def batched_deletion?
      Feature.enabled?(:ml_delete_experiments_in_batches, @model.project)
    end
    strong_memoize_attr :batched_deletion?

    # Validated before the packages are marked for destruction, which the transaction cannot undo.
    def prepare_experiment_deletion
      experiment.model_id = nil
      experiment.assign_deletion_attributes
      experiment.valid?
    end

    def destroy_model
      return @model.destroy unless batched_deletion?

      Ml::Model.transaction do
        # Keeps the versions' candidates out of the ml_model_versions cascade; the worker deletes them.
        # Versions are locked before their candidates, as a version delete does, so the two cannot deadlock.
        # Plucked ids keep the planner on the unique index; a subquery here plans a merge join.
        @model.versions.each_batch(of: VERSIONS_BATCH_SIZE) do |versions|
          version_ids = versions.lock_for_update.pluck_primary_key
          Ml::Candidate.for_model_version_ids(version_ids).update_all(model_version_id: nil)
        end

        raise ActiveRecord::Rollback unless experiment.save && @model.destroy

        true
      end
    end

    def success
      ServiceResponse.success(payload: payload)
    end

    def experiment
      @model.default_experiment
    end
    strong_memoize_attr :experiment

    def error
      messages = @model.errors.full_messages
      messages += experiment.errors.full_messages if batched_deletion?

      ServiceResponse.error(message: messages, payload: payload)
    end

    def packages_not_deleted(error_message)
      ServiceResponse.error(message: error_message, payload: payload)
    end

    def payload
      { model: @model }
    end

    def audit_destroy_event(model)
      audit_context = {
        name: 'ml_model_destroyed',
        author: @user,
        scope: model.project,
        target: model,
        message: "MlModel #{model.name} destroyed"
      }

      ::Gitlab::Audit::Auditor.audit(audit_context)
    end
  end
end
