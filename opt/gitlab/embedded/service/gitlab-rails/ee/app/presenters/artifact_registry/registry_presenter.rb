# frozen_string_literal: true

module ArtifactRegistry
  class RegistryPresenter < ::Gitlab::View::Presenter::Delegated
    presents ::ArtifactRegistry::NamespaceMapping::Registry

    def initialize(subject, organization:) # rubocop:disable Lint/UselessMethodDefinition -- pins the attribute as a required keyword the **attributes parent leaves optional
      super
    end

    def declarative_policy_subject
      organization
    end
  end
end
