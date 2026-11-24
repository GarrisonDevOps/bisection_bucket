# frozen_string_literal: true

module API
  module Entities
    class Package < Grape::Entity
      include ::API::Helpers::RelatedResourcesHelpers
      include ::Routing::PackagesHelper
      extend ::API::Entities::EntityHelpers

      EMPTY_PIPELINES = [].freeze

      expose :id, documentation: { type: 'Integer', format: 'int64', example: 1 }

      expose :name, documentation: { type: 'String', example: '@foo/bar' } do |package|
        if package.conan?
          package.conan_recipe
        else
          package.name
        end
      end

      expose :conan_package_name, if: ->(package) { package.conan? }, &:name

      expose :version, documentation: { type: 'String', example: '1.0.3' }
      expose :package_type, documentation: { type: 'String', example: 'npm' }
      expose :status, documentation: { type: 'String', example: 'default' }

      expose :_links do
        expose :web_path, if: ->(package) { package.detailed_info? } do |package|
          package_path(package)
        end

        expose :delete_api_path, if: can_destroy(:package, &:project) do |package|
          expose_url api_v4_projects_packages_path(package_id: package.id, id: package.project_id)
        end
      end

      expose :created_at, documentation: { type: 'DateTime', example: '2022-09-16T12:47:31.949Z' }
      expose :last_downloaded_at, documentation: { type: 'DateTime', example: '2022-09-19T11:32:35.169Z' }
      expose :creator_id,
        documentation: { type: 'Integer', format: 'int64', example: 1, desc: 'ID of the user who created the package' }
      expose :project_id, documentation: { type: 'Integer', format: 'int64', example: 2 }, if: ->(_, opts) {
        opts[:group]
      }
      expose :project_path, documentation: { type: 'String', example: 'gitlab/foo/bar' }, if: ->(obj, opts) do
        opts[:group] && Ability.allowed?(opts[:user], :read_project, obj.project)
      end
      expose :tags

      expose :pipeline, if: ->(package, opts) {
        can_read_pipeline?(package, opts) && last_build_info(package, opts)
      }, using: Package::Pipeline do |package, opts|
        last_build_info(package, opts).pipeline
      end

      expose :pipelines, if: ->(package, opts) {
        can_read_pipeline?(package, opts) && last_build_info(package, opts)
      }, using: Package::Pipeline, documentation: { is_array: true } do |_package, _opts|
        EMPTY_PIPELINES
      end

      expose :versions, using: ::API::Entities::PackageVersion, unless: ->(_, opts) {
        opts[:collection]
      }, documentation: { is_array: true } do |package, opts|
        opts[:versions] || package.versions
      end

      private

      def project_path
        object.project.full_path
      end

      def can_read_pipeline?(package, opts)
        return false unless Ability.allowed?(opts[:user], :read_pipeline, package.project)

        # The pipeline can belong to another project when published with a cross-project CI_JOB_TOKEN.
        pipeline = last_build_info(package, opts)&.pipeline
        pipeline.nil? || pipeline.project_id == package.project_id ||
          Ability.allowed?(opts[:user], :read_pipeline, pipeline)
      end

      # List endpoints pass the newest build info of every package on the page so that
      # rendering does not query build infos package by package.
      def last_build_info(package, opts)
        return opts[:last_build_infos][package.id] if opts[:last_build_infos]

        package.last_build_info
      end
    end
  end
end
