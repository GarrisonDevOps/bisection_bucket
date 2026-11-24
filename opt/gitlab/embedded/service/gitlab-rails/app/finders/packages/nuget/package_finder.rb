# frozen_string_literal: true

module Packages
  module Nuget
    class PackageFinder < ::Packages::GroupOrProjectPackageFinder
      extend ::Gitlab::Utils::Override

      MAX_PACKAGES_COUNT = 300
      FORCE_NORMALIZATION_CLIENT_VERSION = '>= 3'

      def execute
        return packages_class.none unless @params[:package_name].present?

        result = packages.limit_recent(@params[:limit] || MAX_PACKAGES_COUNT)
        version = @params[:package_version]
        # Equivalent packages share a normalized release version, so the newest of them stays first.
        return result if version.blank? || ::Packages::Nuget::Metadatum.normalized_release_version?(version)

        result.order_exact_version_first(version)
      end

      private

      def packages
        result = find_by_name
        find_by_version(result)
      end

      def find_by_name
        base
          .has_version
          .with_case_insensitive_name(@params[:package_name])
      end

      def find_by_version(result)
        return result if @params[:package_version].blank?

        result
          .with_nuget_version_or_normalized_version(
            @params[:package_version],
            with_normalized: client_forces_normalized_version?
          )
      end

      override :group_packages
      def group_packages
        packages_visible_to_user_including_public_registries(
          @current_user,
          within_group: @project_or_group,
          with_package_registry_enabled: true
        )
      end

      def client_forces_normalized_version?
        return true if @params[:client_version].blank?

        VersionSorter.compare(FORCE_NORMALIZATION_CLIENT_VERSION, @params[:client_version]) <= 0
      end

      override :packages_class
      def packages_class
        ::Packages::Nuget::Package
      end
    end
  end
end
