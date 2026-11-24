# frozen_string_literal: true

module Security
  class VAC
    def self.enabled?(actor)
      # Check the flag against the root namespace so it can be rolled out per-namespace
      # rather than having to be enabled for every project individually.
      flag_actor = actor.is_a?(Project) ? actor.root_namespace : actor
      feature_enabled = Feature.enabled?(:vulnerabilities_across_contexts, flag_actor)
      # Fall back to checking the Feature Flag if we're not handling a Project or we're not on Dedicated.
      return feature_enabled unless actor.is_a?(Project) && Gitlab::Dedicated.feature_available?(:vac_on_dedicated)

      feature_enabled || Gitlab::CurrentSettings.vac_project_ids.include?(actor.id)
    end

    def self.disabled?(actor)
      !enabled?(actor)
    end
  end
end
