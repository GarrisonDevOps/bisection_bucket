# frozen_string_literal: true

module Packages
  module Cleanup
    class ExecutePolicyService
      include Gitlab::Utils::StrongMemoize

      MAX_EXECUTION_TIME = 250.seconds

      PACKAGES_BATCH_SIZE = 500
      MARK_PACKAGE_FILES_FOR_DESTRUCTION_SERVICE_BATCH_SIZE = 200
      NOT_DOWNLOADED_PACKAGES_BATCH_SIZE = 500
      MARK_PACKAGES_FOR_DESTRUCTION_BATCH_SIZE = 100
      NOT_DOWNLOADED_PACKAGES_STATUSES = %i[default hidden error deprecated].freeze
      MAVEN_SNAPSHOT_FILES_BATCH_SIZE = 1_000
      MAVEN_SNAPSHOT_VERSION_SUFFIX = '-SNAPSHOT'

      delegate :project, to: :@policy, private: true

      def initialize(policy)
        @policy = policy
        @counts = {
          marked_package_files_total_count: 0,
          unique_package_id_and_file_name_total_count: 0,
          marked_packages_total_count: 0
        }
      end

      def execute
        # Generic packages go first: marking whole packages is cheap, and a project whose
        # duplicate cleanup always times out would otherwise never reach this rule.
        return response_success(timeout: true) if delete_generic_packages_not_downloaded == :timeout

        response_success(timeout: cleanup_duplicated_files == :timeout)
      end

      private

      def cleanup_duplicated_files
        return if @policy.keep_n_duplicated_package_files_disabled?

        # Batch by package: file-level batches can split a duplicate group and miss it.
        # The each_batch queries use idx_installable_helm_pkgs_on_project_id_id. Despite its name,
        # it is a plain (project_id, id) index with no Helm predicate.
        project.packages.each_batch(of: PACKAGES_BATCH_SIZE) do |packages|
          break :timeout if cleanup_duplicated_files_on(installable_package_files_for(packages)) == :timeout
          break :timeout if cleanup_maven_snapshot_builds_on(packages) == :timeout
        end
      end

      def delete_generic_packages_not_downloaded
        return if @policy.delete_generic_packages_not_downloaded_disabled?
        return unless Feature.enabled?(:packages_cleanup_delete_generic_not_downloaded, project)

        cutoff = @policy.delete_generic_packages_not_downloaded_in_days.days.ago

        NOT_DOWNLOADED_PACKAGES_STATUSES.each do |status|
          result = delete_generic_packages_not_downloaded_with_status(status, cutoff)
          break :timeout if result == :timeout
        end
      end

      # Batches on the (project_id, status, id) index. packages_packages has no index on
      # (project_id, package_type, id) and blocks new ones, so the type filter runs per batch.
      def delete_generic_packages_not_downloaded_with_status(status, cutoff)
        ::Packages::Package.for_projects(project).with_status(status)
          .each_batch(of: NOT_DOWNLOADED_PACKAGES_BATCH_SIZE) do |packages|
          break :timeout if batch_deadline.past?

          package_ids = packages.generic
                                .not_downloaded_since(cutoff)
                                .without_delete_protection_rules
                                .pluck_primary_key
          next if package_ids.empty?

          break :timeout if mark_packages_for_destruction(package_ids) == :timeout
        end
      end

      # Files first: CleanupPackageFileWorker destroys a package once its last file is gone,
      # so a package is never left pending destruction with files that nothing deletes.
      def mark_packages_for_destruction(package_ids)
        package_files = ::Packages::PackageFile.for_package_ids(package_ids)
        result = ::Packages::MarkPackageFilesForDestructionService.new(package_files)
          .execute(batch_deadline: batch_deadline, batch_size: MARK_PACKAGE_FILES_FOR_DESTRUCTION_SERVICE_BATCH_SIZE)

        @counts[:marked_package_files_total_count] += result.payload[:marked_package_files_count]
        return :timeout unless result.success?

        package_ids.each_slice(MARK_PACKAGES_FOR_DESTRUCTION_BATCH_SIZE) do |ids|
          break :timeout if batch_deadline.past?

          @counts[:marked_packages_total_count] +=
            ::Packages::Package.id_in(ids).update_all(status: :pending_destruction)
        end
      end

      def installable_package_files_for(packages)
        ::Packages::PackageFile.installable.for_package_ids(packages)
      end

      def cleanup_duplicated_files_on(package_files)
        unique_package_id_and_file_name_and_package_type_from(package_files)
          .each do |package_id, file_name, package_type|
          result = remove_duplicated_files_for(package_id: package_id, file_name: file_name, package_type: package_type)
          @counts[:marked_package_files_total_count] += result.payload[:marked_package_files_count]
          @counts[:unique_package_id_and_file_name_total_count] += 1

          break :timeout unless result.success?
        end
      end

      def unique_package_id_and_file_name_and_package_type_from(package_files)
        # rubocop: disable CodeReuse/ActiveRecord -- This is a highly custom query for this service, that's why it's not in the model.
        package_files.joins(:package)
                     .group(:package_id, :file_name, "#{::Packages::Package.table_name}.package_type")
                     .having("COUNT(*) > #{@policy.keep_n_duplicated_package_files}")
                     .pluck(:package_id, :file_name, "#{::Packages::Package.table_name}.package_type") # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- one row per duplicate group in a batch of PACKAGES_BATCH_SIZE packages
        # rubocop: enable CodeReuse/ActiveRecord
      end

      def remove_duplicated_files_for(package_id:, file_name:, package_type:)
        base = ::Packages::PackageFile.for_package_ids(package_id)
                 .installable
                 .with_file_name(file_name)

        ids_to_keep = if package_type == 'conan'
                        conan_keep_n_duplicate_ids(base)
                      else
                        base.recent
                          .limit(@policy.keep_n_duplicated_package_files)
                          .pluck_primary_key
                      end

        duplicated_package_files = base.id_not_in(ids_to_keep)
        ::Packages::MarkPackageFilesForDestructionService.new(duplicated_package_files)
          .execute(batch_deadline: batch_deadline, batch_size: MARK_PACKAGE_FILES_FOR_DESTRUCTION_SERVICE_BATCH_SIZE)
      end

      # Snapshot file names carry the build (my-app-1.0-20220922.125608-3.jar), so builds never share
      # a name. Rank each file's copies across builds, so a file only older builds have is kept.
      # Files with no build in the name, like maven-metadata.xml, use the duplicate rule above.
      def cleanup_maven_snapshot_builds_on(packages)
        return unless Feature.enabled?(:packages_cleanup_policy_maven_snapshot_builds, project)

        package_ids = maven_snapshot_package_ids_with_old_builds(packages)
        return if package_ids.empty?

        ::Packages::Package.id_in(package_ids).each do |package|
          break :timeout if remove_old_maven_snapshot_builds_for(package) == :timeout
        end
      end

      # One aggregate per batch, so only packages with more than keep_n copies of a file get their files listed.
      def maven_snapshot_package_ids_with_old_builds(packages)
        # rubocop: disable CodeReuse/ActiveRecord -- This is a highly custom query for this service, that's why it's not in the model.
        build_regex = Gitlab::Regex::Packages::MAVEN_SNAPSHOT_BUILD_SQL_REGEX
        # LIKE, not ILIKE: Maven versions are case-sensitive
        snapshot_packages = packages.maven
          .where(::Packages::Package.arel_table[:version].matches("%#{MAVEN_SNAPSHOT_VERSION_SUFFIX}", nil, true))
        name_without_build = Arel::Nodes::NamedFunction.new(
          'regexp_replace',
          [
            ::Packages::PackageFile.arel_table[:file_name],
            Arel::Nodes.build_quoted(build_regex),
            Arel::Nodes.build_quoted('')
          ]
        )

        ::Packages::PackageFile.installable
          .for_package_ids(snapshot_packages.select(:id))
          .where('file_name ~ ?', build_regex)
          .group(:package_id, name_without_build)
          .having('COUNT(*) > ?', @policy.keep_n_duplicated_package_files.to_i)
          .pluck(:package_id) # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- one row per group over the limit, in a batch of PACKAGES_BATCH_SIZE packages
          .uniq
        # rubocop: enable CodeReuse/ActiveRecord
      end

      def remove_old_maven_snapshot_builds_for(package)
        ids_by_name = Hash.new { |names, name| names[name] = Hash.new { |builds, build| builds[build] = [] } }

        listed = package.installable_package_files.each_batch(of: MAVEN_SNAPSHOT_FILES_BATCH_SIZE) do |package_files|
          break :timeout if batch_deadline.past?

          package_files.pluck(:id, :file_name).each do |id, file_name| # rubocop:disable CodeReuse/ActiveRecord, Database/AvoidUsingPluckWithoutLimit -- package_files is already in batches
            name, build = maven_snapshot_name_and_build_from(file_name)
            ids_by_name[name][build] << id if build
          end
        end
        return :timeout if listed == :timeout

        keep = @policy.keep_n_duplicated_package_files.to_i
        old_ids_by_name = ids_by_name.transform_values do |ids_by_build|
          ids_by_build.sort.reverse.drop(keep).flat_map(&:last)
        end
        old_ids_by_name.reject! { |_name, ids| ids.empty? }
        @counts[:unique_package_id_and_file_name_total_count] += old_ids_by_name.size

        old_ids_by_name.values.flatten.each_slice(MARK_PACKAGE_FILES_FOR_DESTRUCTION_SERVICE_BATCH_SIZE) do |ids|
          break :timeout if batch_deadline.past?

          @counts[:marked_package_files_total_count] +=
            ::Packages::PackageFile.id_in(ids).update_all(status: :pending_destruction)
        end
      end

      # Returns the file name without its build, like my-app-1.0.jar, and the build as
      # [timestamp, build number], which sorts from oldest to newest. Returns nil without a build.
      def maven_snapshot_name_and_build_from(file_name)
        match_data = file_name.match(Gitlab::Regex::Packages::MAVEN_SNAPSHOT_DYNAMIC_PARTS)
        return unless match_data

        build = match_data.captures.last
        timestamp, build_number = build.delete_prefix('-').split('-')
        [file_name.gsub(build, ''), [timestamp, build_number.to_i]]
      end

      def conan_keep_n_duplicate_ids(package_files)
        # rubocop: disable CodeReuse/ActiveRecord -- This is a highly custom query for this service, that's why it's not in the model.
        metadatum = ::Packages::Conan::FileMetadatum.arel_table
        partition = Arel::Nodes::Window.new
                                       .partition(
                                         metadatum[:conan_file_type], metadatum[:recipe_revision_id],
                                         metadatum[:package_revision_id], metadatum[:package_reference_id]
                                       )
        row_number = Arel::Nodes::NamedFunction.new('ROW_NUMBER', [])
                                               .over(
                                                 partition.order(
                                                   ::Packages::PackageFile.arel_table[:created_at].desc
                                                 )
                                               )
                                               .as('rn')

        inner_query = package_files.joins(:conan_file_metadatum).select(:id, row_number)
        cte = Gitlab::SQL::CTE.new(:ranked_files, inner_query)

        ::Packages::PackageFile.with(cte.to_arel)
                               .select(cte.table[:id])
                               .where(cte.table[:rn].lteq(@policy.keep_n_duplicated_package_files))
                               .from(cte.table)
                               .ids
        # rubocop: enable CodeReuse/ActiveRecord
      end

      def batch_deadline
        MAX_EXECUTION_TIME.from_now
      end
      strong_memoize_attr :batch_deadline

      def response_success(timeout:)
        ServiceResponse.success(
          message: "Packages cleanup policy executed for project #{project.id}",
          payload: {
            timeout: timeout,
            counts: @counts
          }
        )
      end
    end
  end
end
