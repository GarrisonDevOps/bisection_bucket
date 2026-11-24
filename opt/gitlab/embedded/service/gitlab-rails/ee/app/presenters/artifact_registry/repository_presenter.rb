# frozen_string_literal: true

module ArtifactRegistry
  # Pairs a repository with the organization it was read through. The value object holds no
  # back-reference, so a connection mounted on the repository type has no other way to reach
  # the slug and the memoized client its own read needs.
  class RepositoryPresenter < ::Gitlab::View::Presenter::Delegated
    presents ::ArtifactRegistry::Repository

    # Points type authorization at the organization, which governs reading a repository.
    #
    # Nothing evaluates it today: the organization-rooted fields skip this ability, and
    # `ObjectAuthorization` subtracts skipped abilities before consulting a policy. It matters
    # if that skip goes. The inherited `declarative_policy_delegate` resolves to the bare value
    # object, which has no policy class, so `DeclarativePolicy.class_for` raises rather than
    # denying -- a 500, not a 403.
    #
    # Overriding that delegate instead would reach a policy but bind it wrongly: `class_for`
    # takes the class from the delegate, `policy_for` instantiates it with the original subject.
    def declarative_policy_subject
      organization
    end
  end
end
