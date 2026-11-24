# frozen_string_literal: true

module Ai
  module DapFactory
    # Makes the project's managed triggers match `.gitlab-dap-factory.yml` on the default branch. The file wins
    # over edits made on the triggers page. An unmanaged trigger with a stage's description is adopted, so two
    # triggers cannot start the same stage.
    class SyncService
      include ::Gitlab::ExclusiveLeaseHelpers
      include ::Gitlab::Loggable

      LEASE_KEY = 'ai:dap_factory:sync'
      TRIGGER_PERMISSIONS = %i[create_ai_flow_trigger update_ai_flow_trigger delete_ai_flow_trigger].freeze
      LEASE_TTL = 5.minutes
      READ_LIMIT = ::Gitlab::Ai::DapFactory::Validator::MAX_BYTES + 1

      WORK_ITEM_EVENT_TYPE = ::Ai::FlowTrigger::EVENT_TYPES[:work_item]
      MERGE_REQUEST_EVENT_TYPE = ::Ai::FlowTrigger::EVENT_TYPES[:merge_request]

      # A work item in another workflow can have the same status, and must not start a stage.
      SOFTWARE_FACTORY_RULE = { 'field' => 'software_factory_enabled', 'operator' => 'in', 'value' => [true] }.freeze

      def initialize(project:, current_user:)
        @project = project
        @current_user = current_user
        @summary = {
          'adopted' => [], 'created' => [], 'updated' => [], 'deleted' => [], 'unchanged' => [], 'failed' => []
        }
      end

      def execute
        in_lock("#{LEASE_KEY}:#{project.id}", ttl: LEASE_TTL, retries: 0) do
          sync
        end
      rescue ::Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
        ServiceResponse.error(message: 'Another Sync is already running for this project', reason: :lease_taken)
      end

      private

      attr_reader :project, :current_user, :summary

      def sync
        commit = project.repository.commit(project.default_branch)
        return failed(nil, 'The default branch has no commits.') unless commit

        unless TRIGGER_PERMISSIONS.all? { |permission| Ability.allowed?(current_user, permission, project) }
          return failed(commit.id, 'The user who pushed cannot manage flow triggers. No triggers were changed.')
        end

        content = read_file(commit)
        return failed(commit.id, 'Could not read the file from the repository. No triggers were changed.') if
          content == :unreadable

        configuration = nil

        unless content.nil?
          result = ::Gitlab::Ai::DapFactory::Validator.new(content: content, project: project).execute
          return invalid(commit.id, result.errors) unless result.valid?

          configuration = result.configuration
        end

        reconcile(configuration)
        finished(commit.id)
      end

      # An absent file removes every managed trigger; a read error must not, so it is told apart. The read is
      # capped so that a huge file is rejected by the Validator without being loaded.
      def read_file(commit)
        project.repository.blob_at(commit.id, ::Gitlab::Ai::DapFactory::Configuration::PATH, limit: READ_LIMIT)&.data
      rescue ::Gitlab::Git::BaseError, GRPC::BadStatus => e
        ::Gitlab::ErrorTracking.track_exception(e, project_id: project.id)
        :unreadable
      end

      def reconcile(configuration)
        existing = project.ai_flow_triggers.factory_managed.index_by(&:factory_stage)
        desired = configuration ? configuration.triggered_stages.index_by(&:key) : {}
        consumer_ids = flow_consumer_ids(desired.values)

        desired.each do |key, stage|
          consumer_id = consumer_ids[stage.flow]
          unless consumer_id
            next record(ServiceResponse.error(message: "#{stage.flow} is not a flow enabled in this project."),
              'created', key)
          end

          params = trigger_params(configuration, stage, consumer_id)
          trigger = existing[key] || adopt_trigger(stage)
          trigger ? update_trigger(trigger, params) : create_trigger(params)
        end

        (existing.keys - desired.keys).each { |key| destroy_trigger(existing[key]) }
      end

      # A miss means the flow was disabled between validation and now; the Validator already required one.
      def flow_consumer_ids(stages)
        flows = stages.map(&:flow).uniq
        return {} if flows.empty?

        ids, references = flows.partition { |flow| flow.is_a?(Integer) }
        items = ::Ai::Catalog::Item.not_deleted.id_in(ids)
          .or(::Ai::Catalog::Item.not_deleted.with_foundational_flow_reference(references)).index_by(&:id)
        consumers = ::Ai::Catalog::ItemConsumer.for_projects(project).by_enabled(true).for_item(items.keys)

        consumers.each_with_object({}) do |consumer, found|
          item = items[consumer.ai_catalog_item_id]
          reference = item.foundational_flow_reference
          found[item.id] = consumer.id if ids.include?(item.id)
          found[reference] = consumer.id if references.include?(reference)
        end
      end

      def description_for(stage)
        stage.merge_request_driven? ? "Software Factory: #{stage.key} loop" : "Software Factory: #{stage.key}"
      end

      # Only a catalog trigger that is not scheduled can become a stage trigger: an external agent trigger would
      # fail validation on every Sync, and a push must not dismantle a scheduled flow.
      def adopt_trigger(stage)
        project.ai_flow_triggers.not_factory_managed.with_catalog_item_consumer.not_triggered_on(:scheduled)
          .with_description(description_for(stage)).ordered_by_id.first
      end

      def trigger_params(configuration, stage, consumer_id)
        {
          description: description_for(stage),
          event_types: [stage.merge_request_driven? ? MERGE_REQUEST_EVENT_TYPE : WORK_ITEM_EVENT_TYPE],
          filter: stage.merge_request_driven? ? requested_changes_filter : status_changed_filter(stage),
          ai_catalog_item_consumer_id: consumer_id,
          status_on_finish: configuration.status_on_finish_for(stage),
          ready_merge_requests_on_finish: stage.mark_merge_requests_ready,
          active: true,
          goals: {},
          factory_stage: stage.key
        }
      end

      def status_changed_filter(stage)
        rules = [
          { 'field' => 'action', 'operator' => 'in', 'value' => ['status_changed'] },
          { 'field' => 'status.name', 'operator' => 'in', 'value' => [stage.status] }
        ]
        rules << SOFTWARE_FACTORY_RULE unless stage.intake?

        { 'work_item' => { 'match' => 'all', 'rules' => rules } }
      end

      # These three rules are the only thing scoping the review loop. FixLoop selects a trigger purely by
      # evaluating this filter since https://gitlab.com/gitlab-org/gitlab/-/merge_requests/268777, so without
      # created_by_flow and draft, Duo Developer runs on merge requests the factory does not own.
      def requested_changes_filter
        {
          'merge_request' => {
            'match' => 'all',
            'rules' => [
              { 'field' => 'action', 'operator' => 'in', 'value' => ['requested_changes'] },
              { 'field' => 'created_by_flow', 'operator' => 'in', 'value' => [true] },
              { 'field' => 'draft', 'operator' => 'in', 'value' => [false] }
            ]
          }
        }
      end

      def create_trigger(params)
        result = ::Ai::FlowTriggers::CreateService.new(project: project, current_user: current_user).execute(params)
        record(result, 'created', params[:factory_stage])
      end

      def update_trigger(trigger, params)
        return summary['unchanged'] << trigger.factory_stage unless trigger_changed?(trigger, params)

        bucket = trigger.factory_stage ? 'updated' : 'adopted'
        result = ::Ai::FlowTriggers::UpdateService.new(project: project, current_user: current_user, trigger: trigger)
          .execute(params)
        record(result, bucket, params[:factory_stage])
      end

      def trigger_changed?(trigger, params)
        current = {
          description: trigger.description,
          event_types: trigger.event_types,
          filter: trigger.filter,
          ai_catalog_item_consumer_id: trigger.ai_catalog_item_consumer_id,
          status_on_finish: trigger.status_on_finish,
          ready_merge_requests_on_finish: trigger.ready_merge_requests_on_finish,
          active: trigger.active,
          goals: trigger.goals,
          factory_stage: trigger.factory_stage
        }

        current != params
      end

      def destroy_trigger(trigger)
        result = ::Ai::FlowTriggers::DestroyService.new(trigger: trigger, current_user: current_user).execute
        record(result, 'deleted', trigger.factory_stage)
      end

      def record(result, bucket, stage)
        return summary[bucket] << stage if result.success?

        log(message: 'DAP Factory Sync could not apply a stage', factory_stage: stage,
          Labkit::Fields::ERROR_MESSAGE => result.message)
        summary['failed'] << { 'stage' => stage, 'message' => result.message }
      end

      def finished(commit_sha)
        status = summary['failed'].empty? ? SyncResult::SYNCED : SyncResult::PARTIAL
        result = save_result(status, commit_sha)

        return ServiceResponse.success(payload: result) if status == SyncResult::SYNCED

        ServiceResponse.error(message: 'Some stages could not be applied', reason: :partial, payload: result)
      end

      def invalid(commit_sha, errors)
        messages = errors.map do |error|
          { 'path' => error.path, 'code' => error.code.to_s, 'message' => error.message }
        end
        result = save_result(SyncResult::INVALID, commit_sha, messages)

        ServiceResponse.error(message: 'The file is not valid. No triggers were changed.', reason: :invalid,
          payload: result)
      end

      def failed(commit_sha, message)
        error = { 'path' => nil, 'code' => 'failed', 'message' => message }
        result = save_result(SyncResult::FAILED, commit_sha, [error])

        ServiceResponse.error(message: message, reason: :failed, payload: result)
      end

      def save_result(status, commit_sha, errors = [])
        SyncResult.new(status: status, commit_sha: commit_sha, synced_at: Time.current, errors: errors,
          summary: summary).save(project)
      end

      def log(message:, **payload)
        ::Gitlab::AppJsonLogger.warn(
          build_structured_payload_labkit(
            Labkit::Fields::LOG_MESSAGE => message,
            Labkit::Fields::GL_PROJECT_ID => project.id,
            **payload
          )
        )
      end
    end
  end
end
