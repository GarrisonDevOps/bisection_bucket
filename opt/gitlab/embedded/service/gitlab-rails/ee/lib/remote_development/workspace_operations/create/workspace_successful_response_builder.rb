# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Create
      class WorkspaceSuccessfulResponseBuilder
        include Messages

        def self.build(context)
          Gitlab::Fp::Result.ok(WorkspaceCreateSuccessful.new(context))
        end
      end
    end
  end
end
