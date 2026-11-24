# frozen_string_literal: true

module Organizations
  module Settings
    class ArtifactRegistryController < ::Organizations::ApplicationController
      include ArtifactRegistryGating

      feature_category :artifact_registry

      # Registered after the gating concern's callback so the flag-off and missing-read-ability
      # refusals keep the response they already had. Every member holds the read ability, so the
      # update ability is the real gate on the settings page, which is what
      # `authorize_admin_organization!` checks despite its name.
      before_action :authorize_admin_organization!

      # An organization with no mapping row has no registry, so this page has nothing to report
      # on. Runs last so the earlier refusals are answered without querying for the row.
      before_action :ensure_artifact_registry_activated!

      def show; end

      private

      def ensure_artifact_registry_activated!
        render_404 unless organization.artifact_registry_activated?
      end
    end
  end
end
