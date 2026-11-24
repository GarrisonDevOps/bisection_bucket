# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Create
      class DevfileFetcher
        include Messages

        # NOTE: This method should be called `load` to follow the convention of other singleton methods,
        #       but that naming causes errors due to conflicts with `Kernel#load`.
        #
        # @param [Hash] context
        # @return [Gitlab::Fp::Result]
        def self.fetch(context)
          initial_result = Gitlab::Fp::Result.ok(context)

          initial_result
            .and_then(method(:validate_agent_config_exists))
            .map(method(:use_default_devfile_yaml_if_devfile_path_is_not_provided))
            .and_then(method(:read_devfile_yaml_from_repo_if_devfile_path_is_provided))
        end

        # @param [Hash] context
        # @return [Gitlab::Fp::Result]
        def self.validate_agent_config_exists(context)
          context => {
            params: {
              agent: Clusters::Agent => agent
            }
          }

          unless agent.unversioned_latest_workspaces_agent_config
            return Gitlab::Fp::Result.err(WorkspaceCreateParamsValidationFailed.new(
              details: "No WorkspacesAgentConfig found for agent '#{agent.name}'",
              context: context
            ))
          end

          Gitlab::Fp::Result.ok(context)
        end

        # @param [Hash] context
        # @return [Hash] context
        def self.use_default_devfile_yaml_if_devfile_path_is_not_provided(context)
          context => {
            params: {
              devfile_path: String | nil => devfile_path
            },
            settings: {
              default_devfile_yaml: String => default_devfile_yaml
            }
          }

          context[:devfile_yaml] = default_devfile_yaml unless devfile_path

          context
        end

        # @param [Hash] context
        # @return [Gitlab::Fp::Result]
        def self.read_devfile_yaml_from_repo_if_devfile_path_is_provided(context)
          context => {
            params: {
              project: Project => project,
              project_ref: String => project_ref,
              devfile_path: String | nil => devfile_path
            }
          }

          return Gitlab::Fp::Result.ok(context) unless devfile_path

          repository = project.repository
          devfile_blob = repository.blob_at_branch(project_ref, devfile_path)

          unless devfile_blob
            return Gitlab::Fp::Result.err(WorkspaceCreateDevfileLoadFailed.new(
              details: "Devfile path '#{devfile_path}' at ref '#{project_ref}' " \
                "does not exist in the project repository",
              context: context
            ))
          end

          unless devfile_blob.data.present?
            return Gitlab::Fp::Result.err(
              WorkspaceCreateDevfileLoadFailed.new(
                details: "Devfile could not be loaded from project",
                context: context
              )
            )
          end

          # NOTE: The devfile_yaml should only be used for storing it in the database and not in any other
          #       later step in the chain.
          context[:devfile_yaml] = devfile_blob.data

          Gitlab::Fp::Result.ok(context)
        end

        private_class_method :validate_agent_config_exists, :use_default_devfile_yaml_if_devfile_path_is_not_provided,
          :read_devfile_yaml_from_repo_if_devfile_path_is_provided
      end
    end
  end
end
