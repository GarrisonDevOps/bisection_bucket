# frozen_string_literal: true

module Cd
  module Rollouts
    class CreateService
      InvalidFlowDefinitionError = Class.new(StandardError)

      def initialize(parent:, current_user: nil, params: {})
        @parent = parent
        @current_user = current_user
        @params = params.dup
      end

      def execute
        if cross_organization_resources?
          return error([_('One or more referenced resources do not belong to the organization.')])
        end

        rollout = build_rollout

        ::ApplicationRecord.transaction do
          rollout.save!

          build_rollout_environments(rollout)
          build_rollout_steps(rollout)
          record_creation_transition(rollout)
        end

        ::Cd::Rollouts::StartWorker.perform_async(rollout.id)

        ServiceResponse.success(payload: { rollout: rollout })
      rescue ActiveRecord::RecordInvalid => e
        error(e.record.errors.full_messages, rollout)
      rescue InvalidFlowDefinitionError => e
        error([e.message], rollout)
      end

      private

      attr_reader :parent, :current_user, :params

      # Ensures every resource resolved from a client-supplied Global ID belongs
      # to the authorized organization, preventing a caller with permission on
      # one organization from referencing another organization's resources.
      def cross_organization_resources?
        version_set = params[:version_set]

        version_set.present? && version_set.organization_id != parent.id
      end

      def build_rollout
        version_set = params[:version_set]
        application = version_set&.application

        ::Cd::Rollout.new(
          organization: parent,
          version_set: version_set,
          application: application,
          application_flow_definition: latest_flow_definition(application)
        )
      end

      # The rollout uses the application's current (latest) flow definition. The
      # association is ordered by version descending, so the first record is the
      # latest. Returns nil when the application has no flow definition yet.
      def latest_flow_definition(application)
        application&.application_flow_definitions&.first
      end

      def build_rollout_environments(rollout)
        names = flow_document(rollout.application_flow_definition)&.environment_names || []

        if names.empty?
          raise InvalidFlowDefinitionError, 'A rollout requires at least one environment from the flow definition'
        end

        environments_by_name = ::Cd::Environment
          .in_organization(parent)
          .with_name(names)
          .preload_environment_driver_bindings
          .index_by(&:name)

        rollout_environments = names.each_with_index.map do |name, index|
          environment = environments_by_name[name]

          if environment.nil?
            raise InvalidFlowDefinitionError, "Flow definition references unknown environment '#{name}'"
          end

          rollout.rollout_environments.create!(
            organization: parent,
            environment: environment,
            driver_binding: environment.environment_driver_bindings.max_by(&:version),
            position: index + 1
          )
        end

        create_deployments(rollout_environments)
      end

      # One Cd::RolloutStep per node, so the flow visualization has per-step state
      # to read. Built now rather than at start, so the tree exists alongside
      # rollout_environments/deployments as soon as the rollout is created.
      def build_rollout_steps(rollout)
        document = flow_document(rollout.application_flow_definition)
        return unless document

        rollout_environments_by_name = rollout.rollout_environments.index_by { |re| re.environment.name }

        steps = ::Cd::RolloutSteps::Builder.new(
          rollout: rollout,
          document: document,
          rollout_environments_by_name: rollout_environments_by_name
        ).steps

        ::Cd::RolloutStep.bulk_insert!(steps)
      end

      # The rollout's creation is the only point at which the requesting user
      # is known synchronously (Cd::Rollouts::StartWorker/StartService run
      # async with no user context), so this is where "who triggered it" is
      # captured in the journal -- see Cd::RolloutTransition.
      def record_creation_transition(rollout)
        return unless current_user

        rollout.rollout_transitions.create!(
          event: 'create',
          from_state: :initial,
          to_state: :pending,
          principal: "user:#{current_user.id}"
        )
      end

      def create_deployments(rollout_environments)
        timestamp = Time.current

        deployments = rollout_environments.flat_map do |rollout_environment|
          services.map do |service|
            ::Cd::Deployment.new(
              organization: parent,
              rollout_environment: rollout_environment,
              service: service,
              created_at: timestamp,
              updated_at: timestamp
            )
          end
        end

        deployment_ids = ::Cd::Deployment.bulk_insert!(deployments, returns: :ids)

        record_deployment_creation_transitions(deployment_ids, timestamp)
      end

      # Journals each deployment's creation with the requesting user as provenance,
      # mirroring the rollout's own creation transition. State transitions are not
      # journaled yet: they need the workflow-event path, which is the only place
      # their principal is known and does not exist yet.
      # TODO: https://gitlab.com/gitlab-org/gitlab/-/work_items/607142
      def record_deployment_creation_transitions(deployment_ids, timestamp)
        return unless current_user

        transitions = deployment_ids.map do |deployment_id|
          ::Cd::DeploymentTransition.new(
            organization: parent,
            deployment_id: deployment_id,
            event: 'create',
            from_state: :initial,
            to_state: :pending,
            principal: "user:#{current_user.id}",
            created_at: timestamp
          )
        end

        # validate: false skips a per-row lookup of the deployment just inserted above.
        ::Cd::DeploymentTransition.bulk_insert!(transitions, validate: false)
      end

      def services
        @services ||= ::Cd::Service.id_in(params[:version_set].version_set_entries.map(&:service_id).uniq)
      end

      # Memoized: build_rollout_environments and build_rollout_steps both need it
      # for the same flow_definition within a single #execute call.
      def flow_document(flow_definition)
        return if flow_definition.blank?

        @flow_document ||= ::Cd::ApplicationFlowDefinitions::Document.new(YAML.safe_load(flow_definition.definition))
      rescue Psych::Exception => e
        raise InvalidFlowDefinitionError, "Flow definition is unparseable: #{e.message}"
      end

      def error(messages, rollout = nil)
        ServiceResponse.error(message: messages, payload: { rollout: rollout })
      end
    end
  end
end
