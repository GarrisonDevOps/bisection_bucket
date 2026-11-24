# frozen_string_literal: true

module Security
  module ProjectTrackedContexts
    # FindOrCreateService encapsulates the logic to find or create `Security::ProjectTrackedContext` records.
    # If the tracked context does not exist, it will be created, but only if it's for the default branch.
    # Otherwise, it expects the context to already exist.
    class FindOrCreateService
      include Gitlab::Utils::StrongMemoize
      include LoggableCreation

      def self.from_pipeline(pipeline, allow_untracked: false)
        # Agentic analyzer: a duo_workflow workload that scanned the default branch (its
        # HEAD now, or at dispatch) binds to the default-branch context (its synthetic ref
        # is ephemeral).
        default_workload = Security::AgenticAnalyzer.default_branch_scan?(pipeline)
        context_ref = pipeline.tracked_context_ref

        new(
          project: pipeline.project,
          context_name: default_workload ? pipeline.project.default_branch_or_main : context_ref,
          # Workload pipelines are always branch-scoped; tag? is always false for them.
          context_type: pipeline.tag? ? :tag : :branch,
          is_default: default_workload || context_ref == pipeline.project.default_branch_or_main,
          allow_untracked: allow_untracked
        )
      end

      def self.project_default_branch(project)
        new(
          project: project,
          context_name: project.default_branch_or_main,
          context_type: :branch,
          is_default: true
        )
      end

      def initialize(**params)
        @project = params[:project]
        @context_name = params[:context_name]
        @context_type = params[:context_type]
        @is_default = params[:is_default]
        @allow_untracked = params[:allow_untracked] || false
        @current_user = params[:current_user]
      end

      attr_reader :project, :context_name, :context_type, :is_default, :allow_untracked, :current_user

      # Like #execute, but raises BusyError when another process holds the context lock,
      # so Sidekiq callers retry the job instead of inspecting the response themselves.
      def execute!
        response = execute

        raise BusyError, response.message if response.reason == :tracked_context_busy

        response
      end

      def execute
        # A previous run may have marked a drift and raised before enqueueing it.
        @traversal_ids_sync_pending = false

        return permission_error unless can_manage_contexts?
        return validation_error unless valid_params?
        return ref_not_found_error if current_user && !ref_exists_in_repository?

        fast_path_response = existing_context_response
        if fast_path_response
          enqueue_pending_traversal_ids_sync
          return fast_path_response
        end

        # Resolved before the lock: default_branch can hit Gitaly, which we keep out of the sec transaction.
        @default_branch_name = project.default_branch_or_main if branch_context? && is_default

        session = ::Gitlab::Database::LoadBalancing::SessionMap.current(::SecApplicationRecord.load_balancer)
        response = session.use_primary do
          Security::ProjectTrackedContext.uncached do
            Security::ProjectTrackedContext.transaction do
              next busy_response unless obtain_lock

              clear_memoization(:existing_context)
              clear_memoization(:existing_default_branch_context)

              existing_context_response || create_or_update_context
            end
          end
        end

        enqueue_pending_traversal_ids_sync
        response
      end

      private

      def create_or_update_context
        return success(updated_default_branch_context) if update_default_branch_context?
        return cant_create_non_default_error unless is_default || allow_untracked

        create_context
      rescue ActiveRecord::RecordInvalid => e
        raise unless e.record.is_a?(Security::ProjectTrackedContext) &&
          e.record.errors.of_kind?(:context_name, :taken)

        clear_memoization(:existing_context)

        existing_context_response || error(e.record)
      end

      def obtain_lock
        connection = Security::ProjectTrackedContext.connection

        # Hold through the outermost sec transaction, without sleeping inside a caller's transaction.
        connection.select_value("SELECT pg_try_advisory_xact_lock(hashtextextended(#{connection.quote(lock_key)}, 0))")
      end

      def busy_response
        # QA::EE::Resource::VulnerabilityItem matches this message; update it there if it changes.
        ServiceResponse.error(
          message: _('Tracked context is being updated. Please try again.'),
          reason: :tracked_context_busy
        )
      end

      def can_manage_contexts?
        return true unless current_user

        Ability.allowed?(current_user, :create_security_project_tracked_ref, project)
      end

      def valid_params?
        context_name.present? &&
          context_type.present? &&
          %w[branch tag].include?(context_type.to_s)
      end

      def ref_exists_in_repository?
        return false unless project.repository_exists?

        case context_type.to_s
        when 'branch'
          project.repository.branch_exists?(context_name)
        when 'tag'
          project.repository.tag_exists?(context_name)
        else
          false
        end
      end

      def permission_error
        ServiceResponse.error(message: 'Permission denied')
      end

      def validation_error
        ServiceResponse.error(message: 'Invalid ref name or type specified')
      end

      def ref_not_found_error
        ServiceResponse.error(message: 'Ref does not exist in repository')
      end

      def lock_key
        return "security:project_tracked_contexts:#{project.id}:default" if is_default

        "security:project_tracked_contexts:#{project.id}:#{context_type}:#{context_name}"
      end

      # Returns a ServiceResponse when a context already exists, or nil when the caller
      # should continue with the create/update logic.
      def existing_context_response
        return unless existing_context.present?

        if existing_context.tracked? || allow_untracked
          mark_traversal_ids_sync_if_drifted(existing_context)

          return success(existing_context)
        end

        ServiceResponse.error(message: 'Context is not tracked')
      end

      def existing_context
        Security::ProjectTrackedContext.for_project(project).for_context_name(context_name)
        .for_context_type(context_type).first
      end
      strong_memoize_attr :existing_context

      def create_context
        state = if !is_default && @allow_untracked
                  Security::ProjectTrackedContext::STATES[:untracked]
                else
                  Security::ProjectTrackedContext::STATES[:tracked]
                end

        tracked_context = Security::ProjectTrackedContext.create(
          project: project,
          context_name: context_name,
          context_type: context_type,
          is_default: is_default,
          state: state,
          uuid_version: Security::ProjectTrackedContext::CONTEXT_AWARE_UUID_VERSION
        )

        unless tracked_context.persisted?
          if tracked_context.errors.of_kind?(:context_name, :taken)
            clear_memoization(:existing_context)
            return existing_context_response || error(tracked_context)
          end

          return error(tracked_context)
        end

        log_created(tracked_context)

        success(tracked_context)
      end

      def success(tracked_context)
        ServiceResponse.success(payload: { tracked_context: tracked_context })
      end

      def error(tracked_context)
        ServiceResponse.error(message: tracked_context.errors.full_messages)
      end

      def cant_create_non_default_error
        ServiceResponse.error(message: 'Expected context to already exist for non-default branches')
      end

      def branch_context?
        context_type.to_s == 'branch'
      end

      def update_default_branch_context?
        branch_context? && is_default && existing_default_branch_context.present?
      end

      def existing_default_branch_context
        project.security_project_tracked_contexts
          .default_branch
          .last
      end
      strong_memoize_attr :existing_default_branch_context

      def updated_default_branch_context
        context = existing_default_branch_context
        context.update!(context_name: @default_branch_name)
        mark_traversal_ids_sync_if_drifted(context)

        context
      end

      def mark_traversal_ids_sync_if_drifted(context)
        return unless Feature.enabled?(:sync_drifted_tracked_context_traversal_ids, project)

        expected_traversal_ids = project.namespace.traversal_ids
        return if context.traversal_ids == expected_traversal_ids

        log_traversal_ids_drift(context, expected_traversal_ids)
        @traversal_ids_sync_pending = true
      end

      def log_traversal_ids_drift(context, expected_traversal_ids)
        message = ::Vulnerabilities::ConsistencyChecks::TrackedContextTraversalIdsCheck::DRIFT_LOG_MESSAGE

        Gitlab::AppJsonLogger.info(
          build_structured_payload_labkit(
            Labkit::Fields::LOG_MESSAGE => message,
            Labkit::Fields::GL_PROJECT_ID => project.id,
            source: 'find_or_create_service',
            tracked_context_id: context.id,
            is_default: context.is_default?,
            stored_root_id: context.traversal_ids.first,
            expected_root_id: expected_traversal_ids.first
          )
        )
      end

      def enqueue_pending_traversal_ids_sync
        return unless @traversal_ids_sync_pending

        @traversal_ids_sync_pending = false
        # Dropped if a caller's transaction rolls back; the next lookup detects the drift again.
        ActiveRecord.after_all_transactions_commit { enqueue_traversal_ids_sync }
      end

      def enqueue_traversal_ids_sync
        ::Security::SyncTrackedContextTraversalIdsWorker.perform_async(project.id)
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_and_raise_for_dev_exception(e, project_id: project.id)
      end
    end
  end
end
