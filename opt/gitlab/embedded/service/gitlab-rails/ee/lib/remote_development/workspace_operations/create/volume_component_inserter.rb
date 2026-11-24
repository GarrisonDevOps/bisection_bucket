# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Create
      class VolumeComponentInserter
        # @param [Hash] context
        # @return [Hash]
        def self.insert(context)
          context => { processed_devfile: Hash => processed_devfile, volume_mounts: Hash => volume_mounts }
          volume_mounts => { data_volume: Hash => data_volume }
          data_volume => {
            name: String => volume_name,
            path: String => volume_path,
          }

          volume_component = {
            name: volume_name,
            volume: {
              size: '50Gi'
            }
          }

          components = processed_devfile.fetch(:components)

          components << volume_component
          components.each do |component|
            next unless component[:container]

            volume_mount = { name: volume_name, path: volume_path }
            (component.fetch(:container)[:volumeMounts] ||= []) << volume_mount
          end

          context
        end
      end
    end
  end
end
