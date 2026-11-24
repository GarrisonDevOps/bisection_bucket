# frozen_string_literal: true

module Gitlab
  module LicenseScanning
    class SbomScanner < ::Gitlab::LicenseScanning::BaseScanner
      include Gitlab::Utils::StrongMemoize

      def self.latest_pipeline(project, ref)
        project.latest_pipeline_with_reports_for_ref(ref, ::Ci::JobArtifact.of_report_type(:sbom))
      end

      def initialize(project, pipeline, user = ::Gitlab::LicenseScanning::UNSCOPED, self_and_project_descendants: false)
        super(project, pipeline, user)
        @self_and_project_descendants = self_and_project_descendants
      end

      def report
        return empty_report if pipeline.blank?

        components = PipelineComponents.new(pipeline: pipeline, user: user,
          self_and_project_descendants: @self_and_project_descendants).fetch
        package_licenses = PackageLicenses.new(components: components, project: project).fetch

        ::Gitlab::Ci::Reports::LicenseScanning::Report.new.tap do |license_scanning_report|
          package_licenses.each do |package_license|
            resolved_licenses = apply_license_overrides_to_package(package_license)

            resolved_licenses.each do |license_hash|
              expression = license_hash["expression"]
              license = license_scanning_report.add_license(
                id: license_hash["spdx_identifier"],
                name: license_hash["name"] || expression,
                url: license_hash["url"]
              )

              license.add_dependency(
                name: package_license.name,
                package_manager: package_license.package_manager,
                path: package_license.path,
                purl_type: package_license.purl_type,
                version: package_license.version
              )
            end
          end
        end
      end
      strong_memoize_attr :report

      def has_data?
        return false if pipeline.blank?

        sbom_reports = ::Ci::JobArtifact.of_report_type(:sbom)
        return pipeline.has_self_or_descendant_reports?(sbom_reports) if @self_and_project_descendants

        pipeline.has_reports?(sbom_reports)
      end

      def results_available?
        return false if pipeline.blank?

        pipeline.complete_or_manual? && has_data?
      end

      def latest_build_for_default_branch
        pipeline = self.class.latest_pipeline(project, project.default_branch)

        return if pipeline.blank?

        pipeline.builds.latest.sbom_generation.last
      end
      strong_memoize_attr :latest_build_for_default_branch

      # add_licenses obtains the licenses for each dependency in the dependencies array, then
      # adds them to the licenses array of each dependency.
      #
      # @param dependencies [Array<Hash>] An array of hashes containing a `purl_type`, `version` and
      # non-normalized `name` attribute, which come from the dependency_files section of the dependency
      # scanning report. These entries do not include license information.
      #
      # @return [void] This method does not return anything. It modifies the `licenses` field of the
      # input `dependencies` array in-place.
      #
      # @example
      #   dependencies = [
      #     {
      #       :name=>"Django", :packager=>"Python (pip)", :package_manager=>"pip",
      #       :version=>"1.11.4", :licenses=>[], :vulnerabilities=>[], :id=>1,
      #       :location=> { :path=>"requirements.txt" }
      #     },
      #     {
      #       :name=>"actioncable", :packager=>"Ruby (Bundler)", :package_manager=>"bundler",
      #       :version=>"5.0.0", :licenses=>[], :vulnerabilities=>[], :id=>2,
      #       :location=> { :path=>"Gemfile.lock" }
      #     },
      #     {
      #       :name=>"actioncable", :packager=>"Ruby (Bundler)", :package_manager=>"bundler",
      #       :version=>"5.0.0", :licenses=>[], :vulnerabilities=>[], :id=>3,
      #       :location=> { :path=>"proj2/Gemfile.lock" }
      #     }
      #   ]
      #   add_licenses(dependencies)
      #   # The `licenses` field of each hash in the `dependencies` array will be updated with appropriate license
      #   # information for each dependency.
      def add_licenses(dependencies)
        package_licenses = PackageLicenses.new(components: build_components(dependencies)).fetch

        dependencies.each do |dependency|
          # convert from package_manager (ie bundler, pip, etc) to purl_type (ie gem, pypi, etc)
          purl_type = ::Sbom::PurlType::Converter.purl_type_for_pkg_manager(dependency[:package_manager])

          normalized_dependency_name = ::Sbom::PackageUrl::Normalizer.new(
            type: purl_type, text: dependency[:name]).normalize_name

          found_package = package_licenses.find do |pl|
            pl.name == normalized_dependency_name && pl.purl_type == purl_type && pl.version == dependency[:version]
          end

          dependency[:licenses] = found_package.licenses.map do |license|
            {
              name: license.name,
              url: ::Gitlab::Ci::Reports::LicenseScanning::License.spdx_url(license.spdx_identifier)
            }
          end
        end
      end

      private

      def apply_license_overrides_to_package(package_license)
        return package_license.licenses unless license_override_applicator.overrides?

        purl = build_purl_for_package(package_license)
        return package_license.licenses unless purl

        result = license_override_applicator.apply(package_license.licenses, purl: purl)

        # LicenseOverrideApplicator returns plain Hashes (string keys), but
        # PackageLicenses returns Hashie::Mash objects (indifferent access).
        # Wrap overrides in Hashie::Mash for type consistency with downstream consumers.
        if result.equal?(package_license.licenses)
          result
        else
          result.map { |h| h.is_a?(Hashie::Mash) ? h : Hashie::Mash.new(h) }
        end
      end

      def build_purl_for_package(package_license)
        return unless package_license.purl_type.present?

        base = "pkg:#{package_license.purl_type}/#{package_license.name}"
        version = package_license.version
        version.present? ? "#{base}@#{version}" : base
      end

      def license_override_applicator
        @license_override_applicator ||= ::Security::LicenseOverrideApplicator.new(project)
      end

      # @param dependencies [Array<Hash>] An array of hashes containing a `package_manager`, `version` and
      # non-normalized `name` attribute.
      #
      # @return [Array<Hashie::Mash>] An array of Hashie::Mash objects containing a `purl_type`, `version`
      # and normalized `name` attribute.
      #
      # @example
      #   dependencies = [
      #     { :name=>"Django", :package_manager=>"pip", :version=>"1.11.4" },
      #     { :name=>"actioncable", :package_manager=>"bundler", :version=>"5.0.0" }
      #   ]
      #   # Output:
      #   # [
      #   #   <Hashie::Mash name="django" purl_type="pypi" version="1.11.4">,
      #   #   <Hashie::Mash name="actioncable" purl_type="gem" version="5.0.0">
      #   # ]
      def build_components(dependencies)
        dependencies.map do |dependency|
          purl_type = ::Sbom::PurlType::Converter.purl_type_for_pkg_manager(dependency[:package_manager])

          Hashie::Mash.new(
            name: ::Sbom::PackageUrl::Normalizer.new(type: purl_type, text: dependency[:name]).normalize_name,
            purl_type: purl_type,
            version: dependency[:version])
        end
      end
    end
  end
end
