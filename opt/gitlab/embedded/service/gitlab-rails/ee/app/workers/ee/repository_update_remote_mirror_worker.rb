# frozen_string_literal: true

module EE
  module RepositoryUpdateRemoteMirrorWorker # rubocop:disable Gitlab/BoundedContexts -- EE mixin for a CE worker outside a bounded context
    extend ::Gitlab::Utils::Override

    override :repository_mirroring_blocked?
    def repository_mirroring_blocked?(project)
      ::Import::Sync::Projects::WritePolicy.repository_mirroring_blocked?(project)
    end
  end
end
