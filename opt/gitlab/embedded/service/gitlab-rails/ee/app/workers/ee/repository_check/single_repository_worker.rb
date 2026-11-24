# frozen_string_literal: true

module EE
  module RepositoryCheck
    module SingleRepositoryWorker
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      override :perform
      def perform(project_id)
        super unless ::Gitlab::Geo.replica_project_id?(project_id)
      end
    end
  end
end
