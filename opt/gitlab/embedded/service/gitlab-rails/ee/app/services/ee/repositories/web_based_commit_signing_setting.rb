# frozen_string_literal: true

module EE
  module Repositories
    module WebBasedCommitSigningSetting
      extend ::Gitlab::Utils::Override
      override :sign_commits?
      def sign_commits?
        return super unless ::Gitlab::Saas.feature_available?(:repositories_web_based_commit_signing)

        actor = repository.project || repository.group
        return false unless actor

        actor.web_based_commit_signing_enabled
      end
    end
  end
end
