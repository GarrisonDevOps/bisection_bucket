# frozen_string_literal: true

module Ci
  class JobArtifactPolicy < BasePolicy
    def self.preload_for_batch_checks(artifacts, _user)
      ActiveRecord::Associations::Preloader.new(records: artifacts, associations: { job: [:project, :pipeline] }).call
    end

    # Authorized on the artifact's access attributes so equal artifacts share one evaluation
    delegate { ::Authz::JobArtifactAccess.for(@subject) }
  end
end
