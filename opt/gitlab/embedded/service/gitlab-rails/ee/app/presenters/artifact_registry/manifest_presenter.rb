# frozen_string_literal: true

module ArtifactRegistry
  # The manifest value object carries no image id and no back-reference to its read
  # context, so this presenter is how the referrers connection (keyed on the image id
  # and digest pair) reaches that context.
  class ManifestPresenter < ::Gitlab::View::Presenter::Delegated
    presents ::ArtifactRegistry::ManifestDetail

    # The organization is derived from the repository (a RepositoryPresenter) rather than taken
    # as a separate keyword, so a caller cannot pair one organization's repository with another's.
    def initialize(subject, repository:, image_id:)
      super(subject, repository: repository, organization: repository.organization, image_id: image_id)
    end

    # Nothing evaluates this today because the organization-rooted field skips the ability.
    # It matters only if that skip is removed: the delegate would otherwise resolve to the
    # bare value object, which has no policy class, making DeclarativePolicy.class_for raise.
    def declarative_policy_subject
      organization
    end
  end
end
