# frozen_string_literal: true

module API
  module Entities
    class PackageVersion < Grape::Entity
      expose :id
      expose :version
      expose :created_at
      expose :tags

      expose :pipeline, if: ->(package, opts) {
        can_read_pipeline?(package, opts) && last_build_info(package, opts)
      }, using: Package::Pipeline do |package, opts|
        last_build_info(package, opts).pipeline
      end

      private

      def can_read_pipeline?(package, opts)
        return false unless Ability.allowed?(opts[:user], :read_pipeline, package.project)

        # The pipeline can belong to another project when published with a cross-project CI_JOB_TOKEN.
        pipeline = last_build_info(package, opts)&.pipeline
        pipeline.nil? || pipeline.project_id == package.project_id ||
          Ability.allowed?(opts[:user], :read_pipeline, pipeline)
      end

      def last_build_info(package, opts)
        return opts[:last_build_infos][package.id] if opts[:last_build_infos]

        package.last_build_info
      end
    end
  end
end
