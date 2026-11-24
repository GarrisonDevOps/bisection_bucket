# frozen_string_literal: true

module API
  module Entities
    class PackageFile < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64', example: 225 }
      expose :package_id, documentation: { type: 'Integer', format: 'int64', example: 4 }
      expose :created_at, documentation: { type: 'DateTime', example: '2018-11-07T15:25:52.199Z' }
      expose :file_name, documentation: { type: 'String', example: 'my-app-1.5-20181107.152550-1.jar' }
      expose :size, documentation: { type: 'Integer', example: 2421 }
      expose :file_md5, documentation: { type: 'String', example: '58e6a45a629910c6ff99145a688971ac' }
      expose :file_sha1, documentation: { type: 'String', example: 'ebd193463d3915d7e22219f52740056dfd26cbfe' }
      expose :file_sha256, documentation: { type: 'String', example: 'a903393463d3915d7e22219f52740056dfd26cbfeff321b' }
      expose :pipelines, if: ->(package_file, opts) {
        readable_pipelines(package_file, opts).present?
      }, using: Package::Pipeline, documentation: { is_array: true } do |package_file, opts|
        readable_pipelines(package_file, opts)
      end

      private

      def readable_pipelines(package_file, opts)
        return [] unless Ability.allowed?(opts[:user], :read_pipeline, package_file.project)

        # The pipeline can belong to another project when published with a cross-project CI_JOB_TOKEN.
        package_file.pipelines.select do |pipeline|
          pipeline.project_id == package_file.project_id || Ability.allowed?(opts[:user], :read_pipeline, pipeline)
        end
      end
    end
  end
end
