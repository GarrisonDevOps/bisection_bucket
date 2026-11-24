# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Reconcile
      module Output
        # noinspection RubyLiteralArrayInspection
        class ConfigToApplyBuilder
          include WorkspaceOperationsConstants

          ALLOWLIST_WHEN_STATE_TERMINATED = Set.new([
            /#{SECRETS_INVENTORY}$/o,
            /#{WORKSPACE_INVENTORY}$/o
          ])

          # @param [RemoteDevelopment::Workspace] workspace
          # @param [Boolean] include_all_resources
          # @param [RemoteDevelopment::WorkspaceOperations::DesiredConfig] desired_config
          # @return [Array<Hash>]
          def self.build(workspace:, include_all_resources:, desired_config:)
            env_secret_name = "#{workspace.name}#{ENV_VAR_SECRET_SUFFIX}"
            file_secret_name = "#{workspace.name}#{FILE_SECRET_SUFFIX}"
            desired_config_array = desired_config.symbolized_desired_config_array

            config_to_apply = desired_config_array # Start with the persisted desired_config_array and then mutate it

            return select_only_configmaps(config_to_apply: config_to_apply) if workspace.desired_state_terminated?

            inject_secrets(
              config_to_apply: config_to_apply,
              env_secret_name: env_secret_name,
              file_secret_name: file_secret_name,
              workspace: workspace
            )

            update_spec_replicas(
              config_to_apply: config_to_apply,
              workspace: workspace
            )

            filter_partial_resources(config_to_apply: config_to_apply) unless include_all_resources

            config_to_apply
          end

          # @param [Array<Hash>] config_to_apply
          # @return [Array<Hash>]
          def self.select_only_configmaps(config_to_apply:)
            config_to_apply.select! do |object|
              object.fetch(:kind) == "ConfigMap" && ALLOWLIST_WHEN_STATE_TERMINATED.any? do |regex|
                object.dig(:metadata, :name) =~ regex
              end
            end

            config_to_apply
          end

          # Mutates `config_to_apply` and inject secret data in the `env_secret_name`
          #
          # @param [Array<Hash>] config_to_apply
          # @param [String] env_secret_name
          # @param [String] file_secret_name
          # @param [RemoteDevelopment::Workspace] workspace
          # @return [Array<Hash>]
          def self.inject_secrets(config_to_apply:, env_secret_name:, file_secret_name:, workspace:)
            append_secret_data_from_variables(
              config_to_apply: config_to_apply,
              secret_name: env_secret_name,
              variables: workspace.workspace_variables.with_variable_type_environment
            )

            append_secret_data_from_variables(
              config_to_apply: config_to_apply,
              secret_name: file_secret_name,
              variables: workspace.workspace_variables.with_variable_type_file
            )

            append_secret_data(
              config_to_apply: config_to_apply,
              secret_name: file_secret_name,
              data: { WORKSPACE_RECONCILED_ACTUAL_STATE_FILE_NAME.to_sym => workspace.actual_state }
            )

            config_to_apply
          end

          # Mutates `config_to_apply` to remove resources not applicable for partial reconciliation
          #
          # @param [Array] config_to_apply
          # @param [String] secret_name
          # @param [ActiveRecord::Relation<RemoteDevelopment::WorkspaceVariable>] variables
          # @return [void]
          def self.append_secret_data_from_variables(config_to_apply:, secret_name:, variables:)
            data = variables.each_with_object({}) do |workspace_variable, hash|
              hash[workspace_variable.key.to_sym] = workspace_variable.value
            end

            append_secret_data(
              config_to_apply: config_to_apply,
              secret_name: secret_name,
              data: data
            )

            nil
          end

          # @param [Array] config_to_apply
          # @param [String] secret_name
          # @param [Hash] data
          # @return [Array<Hash>]
          # noinspection RubyUnusedLocalVariable -- Rubymine doesn't recognize '^' to use a variable in pattern-matching
          def self.append_secret_data(config_to_apply:, secret_name:, data:)
            config_to_apply => [
              *_,
              {
                metadata: {
                  name: ^secret_name
                },
                data: secret_data
              },
              *_
            ]

            transformed_data = data.transform_values { |value| Base64.strict_encode64(value) }

            secret_data.merge!(transformed_data)

            config_to_apply
          end

          # @param [Array<Hash>] config_to_apply
          # @param [RemoteDevelopment::Workspace] workspace
          # @return [Array<Hash>]
          def self.update_spec_replicas(config_to_apply:, workspace:)
            config_to_apply => [
              *_,
              {
                kind: "Deployment",
                spec: deployment_spec
              },
              *_
            ]

            deployment_spec[:replicas] = workspace.desired_state_running? ? 1 : 0

            config_to_apply
          end

          # @param [Array<Hash>] config_to_apply
          # @return [Array<Hash>]
          def self.filter_partial_resources(config_to_apply:)
            config_to_apply.select! do |object|
              object.dig(:metadata, :annotations, ANNOTATION_KEY_INCLUDE_IN_PARTIAL_RECONCILIATION).present?
            end

            config_to_apply
          end

          private_class_method :select_only_configmaps,
            :inject_secrets,
            :append_secret_data_from_variables,
            :append_secret_data,
            :update_spec_replicas,
            :filter_partial_resources
        end
      end
    end
  end
end
