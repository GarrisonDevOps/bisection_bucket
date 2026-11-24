# frozen_string_literal: true

module ArtifactRegistry
  # Pairs an artifact value object (a package or an image) with the repository it was read
  # through and the organization that repository was read through. The value object holds no
  # back-reference, so a child connection mounted on the artifact element -- the versions list
  # on a package, the manifests list on an image -- has no other way to reach the slug, the
  # repository name and format, and the memoized client its own read needs.
  #
  # One presenter covers both artifact families: the wrapped value object is what discriminates,
  # and the package union unwraps the presenter before matching its member type.
  class ArtifactPresenter < ::Gitlab::View::Presenter::Delegated
    presents ::ArtifactRegistry::MavenPackage, ::ArtifactRegistry::NpmPackage, ::ArtifactRegistry::Image

    # The organization is derived from the repository (a RepositoryPresenter) rather than taken
    # as a second keyword, so a caller cannot pair one organization's repository with another's.
    def initialize(subject, repository:)
      super(subject, repository: repository, organization: repository.organization)
    end

    # Points type authorization at the organization, which governs reading an artifact. Mirrors
    # `RepositoryPresenter`: nothing evaluates it today because the organization-rooted fields
    # skip this ability, but if that skip goes the inherited `declarative_policy_delegate`
    # resolves to the bare value object, which has no policy class, so `DeclarativePolicy.class_for`
    # raises -- a 500, not a 403. Overriding the subject points the lookup at a policied object.
    def declarative_policy_subject
      organization
    end
  end
end
