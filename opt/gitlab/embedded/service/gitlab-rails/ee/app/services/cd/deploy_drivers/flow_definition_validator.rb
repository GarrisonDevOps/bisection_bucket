# frozen_string_literal: true

module Cd
  module DeployDrivers
    # Two layers: the whole document against the orchestration engine's schema, then
    # driver-owned parts against the driver's. The document layer runs first and stops the
    # pass, since a document the engine rejects has none of the shape the driver walk
    # assumes. Run at rollout start, so a driver rebinding cannot leave a stale config
    # undetected.
    class FlowDefinitionValidator
      def initialize(document:, drivers:, organization_id:)
        @document = document
        @drivers = drivers
        @organization_id = organization_id
      end

      def errors
        @errors ||= collect_errors
      end

      def valid?
        errors.empty?
      end

      private

      attr_reader :document, :drivers, :organization_id

      def collect_errors
        return [] if document.nil?

        document_errors = schema_errors(flow_definition_schemer, document, 'flow definition')
        return document_errors if document_errors.any?

        [*environment_service_errors(document), *step_errors(document)]
      end

      def environment_service_errors(document)
        document.fetch('environments', {}).flat_map do |environment_name, environment_config|
          next [] unless environment_config.is_a?(Hash)

          environment_config.fetch('services', {}).flat_map do |service_name, service_environment|
            context = "environment '#{environment_name}' service '#{service_name}'"
            schema_errs = schema_errors_any(application_environment_schemers, service_environment, context)
            next schema_errs if schema_errs.any?

            manifest_repository_errors(service_environment, context)
          end
        end
      end

      # manifest_repository.project is an Argo-driver-specific field (see the
      # gitlab-deploy-driver-argo-rollouts gem's service_environment.json schema), not
      # a generic part of the flow definition -- same narrow, Beta-only exception as
      # cluster_agent_id in Cd::Rollouts::WorkflowKwargs. Checked only once the schema
      # above confirms the shape, and only for a repository on this instance: a project
      # on another GitLab instance is not something this instance can resolve.
      #
      # Scoped to organization_id rather than a plain existence check: unscoped, this
      # would let anyone who can author a flow definition or start a rollout probe
      # whether an arbitrary private project exists anywhere on the instance. A project
      # in a different organization is therefore reported identically to one that
      # doesn't exist at all, so the response carries no information beyond "usable
      # here or not".
      def manifest_repository_errors(service_environment, context)
        manifest_repository = service_environment['manifest_repository']
        return [] unless manifest_repository.is_a?(Hash) && manifest_repository['type'] == 'gitlab'
        return [] unless same_gitlab_instance?(manifest_repository['host'])

        project_path = manifest_repository['project']
        project = ::Project.find_by_full_path(project_path)
        return [] if project.present? && project.organization_id == organization_id

        ["#{context}: manifest_repository project '#{project_path}' does not exist or is not accessible."]
      end

      def same_gitlab_instance?(host)
        host.present? && normalize_host(host) == normalize_host(::Gitlab.config.gitlab.url)
      end

      def normalize_host(url)
        url.to_s.sub(%r{/+\z}, '').downcase
      end

      def step_errors(document)
        ::Cd::ApplicationFlowDefinitions::Document.new(document).driver_steps.flat_map do |step|
          schema_errors_any(steps_schemers, step, "step targeting environment '#{step['environment']}'")
        end
      end

      # Compiled once, not per step and per service.
      def flow_definition_schemer
        @flow_definition_schemer ||= JSONSchemer.schema(::Cd::DeployDrivers::Registry.orchestrator.flow_definition_schema)
      end

      def application_environment_schemers
        @application_environment_schemers ||= drivers.map do |driver|
          JSONSchemer.schema(driver.application_environment_schema)
        end
      end

      def steps_schemers
        @steps_schemers ||= drivers.map { |driver| JSONSchemer.schema(driver.steps_schema) }
      end

      def schema_errors(schemer, value, context)
        schemer.validate(value).map { |error| "#{context}: #{error['error']}" }
      end

      def schema_errors_any(schemers, value, context)
        return [] if schemers.empty? || schemers.any? { |schemer| schemer.valid?(value) }

        schema_errors(schemers.first, value, context)
      end
    end
  end
end
