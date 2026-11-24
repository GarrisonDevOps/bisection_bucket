# frozen_string_literal: true

module Packages
  module MlModel
    class CreatePackageFileService < BaseService
      REPLACE_LIMIT = 100

      def execute
        @package = params[:package]

        return unless @package

        package_file = ::Packages::Package.transaction do
          update_package
          create_package_file
        end

        replace_files_with_same_name(package_file)

        package_file
      end

      private

      attr_reader :package

      def update_package
        package.update_column(:status, params[:status]) if params[:status] && params[:status] != package.status

        package.create_build_infos!(params[:build])
      end

      def create_package_file
        file_params = {
          file: params[:file],
          size: params[:file].size,
          file_sha256: params[:file].sha256,
          file_name: URI.encode_uri_component(params[:file_name]),
          build: params[:build]
        }

        ::Packages::CreatePackageFileService.new(package, file_params).execute
      end

      # MLflow clients overwrite an artifact when they log the same path again.
      # One bounded statement per upload; later uploads of the name mark the rest.
      def replace_files_with_same_name(package_file)
        marked_count = package.package_files
          .installable
          .with_file_name(package_file.file_name)
          .created_before_id(package_file.id)
          .limit(REPLACE_LIMIT)
          .update_all(status: :pending_destruction)

        log_limit_reached(marked_count) if marked_count == REPLACE_LIMIT
      rescue ActiveRecord::ActiveRecordError => e
        # The upload has committed: a failure here must not fail it, or the client uploads the file again.
        Gitlab::ErrorTracking.track_exception(e, Labkit::Fields::GL_PROJECT_ID => project.id, package_id: package.id)
      end

      def log_limit_reached(marked_count)
        Gitlab::AppLogger.info(
          message: 'Model registry file replacement reached the limit',
          Labkit::Fields::GL_PROJECT_ID => project.id,
          package_id: package.id,
          marked_package_files_count: marked_count
        )
      end
    end
  end
end
