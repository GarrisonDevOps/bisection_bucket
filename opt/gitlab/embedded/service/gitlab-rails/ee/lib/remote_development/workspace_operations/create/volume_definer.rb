# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Create
      # NOTE: Even though all this class currently does is define fixed values for volume mounts,
      #       we may want to add more logic to this class in the future, possibly to allow users
      #       control over the configuration of the volume mounts.
      class VolumeDefiner
        include CreateConstants

        # @param [Hash] context
        # @return [Hash]
        def self.define(context)
          # volume_mounts.data_volume.path is set to WORKSPACE_DATA_VOLUME_PATH, as DevfileParser gem uses this value
          # when setting env vars PROJECTS_ROOT and PROJECT_SOURCE that are available within the spawned containers.
          # Hence, workspace_data_volume_path will be used across containers/initContainers as the place for user data.
          #
          # TODO: https://gitlab.com/gitlab-org/gitlab/-/issues/408450
          #       explore in depth implications of PROJECTS_ROOT and PROJECT_SOURCE env vars with devfile team
          #       and update devfile processing to use them idiomatically / conform to devfile specifications

          tools_dir = "#{WORKSPACE_DATA_VOLUME_PATH}/#{TOOLS_DIR_NAME}"

          context.merge(
            tools_dir: tools_dir,
            volume_mounts: {
              data_volume: {
                name: WORKSPACE_DATA_VOLUME_NAME,
                path: WORKSPACE_DATA_VOLUME_PATH
              }
            }
          )
        end
      end
    end
  end
end
