# frozen_string_literal: true

module EE
  module Pages
    module DeploymentUploader
      extend ::Gitlab::Utils::Override

      override :trim_filename_if_needed
      def trim_filename_if_needed(filename)
        # Don't trim the filename on Geo secondary or org migration target to maintain
        # consistency. Otherwise, Geo may not find the page deployments in the object
        # storage during replication or verification due to the trimmed filename.
        #
        # Issue: https://gitlab.com/gitlab-org/gitlab/-/issues/559196
        #
        # model.project can be nil during the initial cache! triggered by
        # assign_attributes, because ActiveRecord sets the inverse association
        # (project) after processing the attributes hash. The filename is
        # resolved again at store! time when the association is available.
        return super if model.project.nil?
        return super unless ::Gitlab::Geo.replica_project?(model.project)

        filename
      end
    end
  end
end
