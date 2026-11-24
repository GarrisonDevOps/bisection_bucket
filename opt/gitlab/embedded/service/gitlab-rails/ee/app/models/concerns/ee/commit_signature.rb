# frozen_string_literal: true

module EE
  module CommitSignature # rubocop:disable Gitlab/BoundedContexts -- module already exists in CE
    extend ::Gitlab::Utils::Override

    override :verified_committer?
    def verified_committer?
      super || verified_ca?
    end
  end
end
