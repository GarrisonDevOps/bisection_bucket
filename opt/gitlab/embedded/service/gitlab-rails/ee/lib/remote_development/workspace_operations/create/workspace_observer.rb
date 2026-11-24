# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Create
      class WorkspaceObserver
        include Messages
        extend Gitlab::Fp::MessageSupport

        # @param [Hash] context
        # @return [void]
        def self.observe(context)
          context => {
            user: user,
            internal_events_class: internal_events_class,
            params: {
              project: project,
            }
          }

          internal_events_class.track_event('create_workspace_result', category: name, project: project,
            namespace: project.namespace, user: user,
            additional_properties: { label: "succeed" })

          nil
        end
      end
    end
  end
end
