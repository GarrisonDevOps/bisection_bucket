# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Create
      class WorkspaceErrorsObserver
        include Messages
        extend Gitlab::Fp::MessageSupport

        # @param [RemoteDevelopment::Message] message
        # @return [void]
        def self.observe(message)
          message.content => {
                    context: {
                      user: user,
                      internal_events_class: internal_events_class,
                      params: {
                        project: project,
                      },
                    }
                  }

          internal_events_class.track_event('create_workspace_result', category: name, project: project,
            namespace: project.namespace, user: user,
            additional_properties: { label: "failed", property: message.class.name.demodulize })

          nil
        end
      end
    end
  end
end
