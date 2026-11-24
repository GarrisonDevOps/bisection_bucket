# frozen_string_literal: true

module Ai
  module Catalog
    module Skills
      # Reconciles a project's AI Catalog skill items against the `skills/<name>/SKILL.md` files on
      # its default branch. One run is a Publish.
      #
      # Writes ActiveRecord directly: Items::BaseCreateService and BaseUpdateService both require a
      # current_user, neither can create-or-update, and neither can skip minting an Item Version.
      # SeedFoundationalFlowsService and ThirdPartyFlows::Seeder bypass them for the same reasons.
      class PublishService
        include ::Gitlab::Utils::StrongMemoize
        include ::Gitlab::ExclusiveLeaseHelpers
        include ::Gitlab::Loggable

        LEASE_KEY = 'ai:catalog:skills:publish'
        LEASE_TTL = 10.minutes

        # Always all six, so a caller never has to check for a key.
        BUCKETS = %i[created updated deleted unchanged failed unpublishable].freeze

        def initialize(project:)
          @project = project
          @summary = BUCKETS.index_with { [] }
        end

        # @return [ServiceResponse] success carries the BUCKETS payload; errors use :scan_failed or
        #   :lease_taken
        def execute
          in_lock("#{LEASE_KEY}:#{project.id}", ttl: LEASE_TTL, retries: 0) do
            # Reconciling deletions against an unknown tree would empty the project's catalog on a
            # transient Gitaly error. Called here so the Gitaly read happens inside the lease.
            next scan_failed_response if scan.nil?

            reconcile

            ServiceResponse.success(payload: summary)
          end
        rescue ::Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
          ServiceResponse.error(message: 'Another publish is already running for this project',
            reason: :lease_taken)
        end

        private

        attr_reader :project, :summary

        # Deleting on rejection would take the item's versions and every consumer with it, so a typo
        # in YAML front matter would revoke a skill everywhere it is used. A rejected path is left
        # untouched; labelling it stale needs https://gitlab.com/gitlab-org/gitlab/-/issues/630881.
        def reconcile
          discovered_by_path = scan.skills.index_by(&:path)
          rejected_by_path = scan.rejections.group_by(&:path)
          existing = existing_by_path

          discovered_by_path.each do |path, skill|
            item = existing[path]
            item ? update_item(item, skill) : create_item(skill)
          end

          rejected_by_path.each { |path, rejections| record_unpublishable(path, rejections) }

          reconcile_deletions(existing, discovered_by_path.keys + rejected_by_path.keys)
        end

        # A truncated scan did not read every file, so an absent path proves nothing.
        def reconcile_deletions(existing, seen_paths)
          return if scan.truncated?

          (existing.keys - seen_paths).each { |path| delete_item(existing[path]) }
        end

        # Identity is the file path, so renaming a skill directory deletes the item and creates a
        # new one. Tracked in https://gitlab.com/gitlab-org/gitlab/-/issues/630884
        def existing_by_path
          by_path = ::Ai::Catalog::Item
            .for_project(project)
            .with_item_type(::Ai::Catalog::Item::SKILL_TYPE)
            .not_deleted
            .preload_latest_version
            .order_by_id_asc
            .group_by { |item| item.latest_version.def_path }

          # More than one item per path is an integrity fault worth reporting. The oldest wins,
          # which is arbitrary but stable across publishes.
          by_path.each { |path, items| log_drift(path, items) if items.size > 1 }

          by_path.transform_values(&:first)
        end

        def create_item(skill)
          item = ::Ai::Catalog::Item.new(
            item_type: ::Ai::Catalog::Item::SKILL_TYPE,
            name: skill.name,
            description: skill.description,
            organization: organization,
            project: project,
            visibility: skill.visibility
          )
          item.build_new_version(version_attributes(skill).merge(version: ::Ai::Catalog::BaseService::DEFAULT_VERSION))

          summary[:created] << skill.path if save_item(item)
        end

        # A refused visibility reduction surfaces through save_item rather than silently leaving the
        # repository and the catalog disagreeing.
        def update_item(item, skill)
          item.assign_attributes(
            name: skill.name,
            description: skill.description,
            visibility: skill.visibility
          )

          # Assigning an unsaved version nulls latest_version_id, so changed? covers that too.
          prepare_version(item, skill)

          return summary[:unchanged] << skill.path unless item.changed?

          # After the changed? check, so an unchanged Publish stays free. Ids that already match
          # cannot affect that check. See #organization.
          item.assign_attributes(organization: organization, project: project)

          summary[:updated] << skill.path if save_item(item)
        end

        # Reported by path, not by item: a skill that has never published has no item, and none can
        # be created because Item validates latest_version.
        def record_unpublishable(path, rejections)
          summary[:unpublishable] << { path: path, errors: rejections.map(&:message) }
        end

        # A released version is frozen by ItemVersion#validate_readonly, so changed content has to
        # mint a new one. Minor bumps, matching the design document's default.
        def prepare_version(item, skill)
          latest = item.latest_version
          return if latest.def_blob_sha == skill.blob_sha && latest.def_git_ref == default_branch

          item.build_new_version(version_attributes(skill).merge(version: item.next_version_number))
        end

        def version_attributes(skill)
          commit = last_commit_for_path(skill.path)

          {
            schema_version: ::Ai::Catalog::ItemVersion::SKILL_SCHEMA_VERSION,
            definition: {
              'path' => skill.path,
              'git_ref' => default_branch,
              'blob_sha' => skill.blob_sha,
              'commit_sha' => commit&.id,
              'author_name' => commit&.author_name,
              'license' => skill.license,
              'compatibility' => skill.compatibility,
              'allowed_tools' => skill.allowed_tools
            }.compact,
            release_date: Time.current,
            created_by: commit&.author
          }
        end

        # A Publish has no user session, so provenance comes from the commit that produced the blob.
        # The git author name is kept alongside created_by, because git attribution is a name and an
        # email that need not match a GitLab user. Only called for a skill that changed.
        def last_commit_for_path(path)
          project.repository.last_commit_for_path(default_branch, path)
        rescue ::Gitlab::Git::BaseError => e
          # Attribution is cosmetic; losing it must not fail a Publish.
          ::Gitlab::ErrorTracking.track_exception(e, project_id: project.id, path: path)
          nil
        end

        def save_item(item)
          ::Ai::Catalog::Item.transaction do
            item.save!
            # The version has to exist before the pointer can reference it.
            item.update!(latest_released_version: item.latest_version) if item.latest_version.released?
          end

          true
        rescue ActiveRecord::RecordInvalid => e
          record_failure(item.latest_version.def_path, e.record.errors.full_messages)

          false
        end

        def delete_item(item)
          path = item.latest_version.def_path

          return summary[:deleted] << path if item.soft_delete

          # One item the database refuses to touch must not abort the rest of the Publish.
          record_failure(path, item.errors.full_messages)
        end

        def record_failure(path, messages)
          log(message: 'Failed to publish skill', path: path, errors: messages)
          summary[:failed] << { path: path, errors: messages }
        end

        def scan_failed_response
          ServiceResponse.error(
            message: 'Could not read skills from the repository. No items were changed.',
            reason: :scan_failed
          )
        end

        # @return [RepositoryScanner::ScanResult, nil] nil when the repository could not be read
        def scan
          ::Gitlab::Ai::Catalog::Skills::RepositoryScanner.new(project).scan
        end
        strong_memoize_attr :scan

        # Records, not ids: Item validates organization for presence and matches it against
        # project.organization_id, so ids make both validations load a row per skill. Memoised
        # because every skill in one Publish shares this project and this organization.
        def organization
          project.organization
        end
        strong_memoize_attr :organization

        def default_branch
          project.default_branch
        end
        strong_memoize_attr :default_branch

        def log_drift(path, items)
          log(
            message: 'Multiple AI Catalog skill items share one path',
            path: path,
            item_ids: items.map(&:id)
          )
        end

        def log(message:, **payload)
          ::Gitlab::AppJsonLogger.warn(
            build_structured_payload_labkit(
              Labkit::Fields::LOG_MESSAGE => message,
              Labkit::Fields::GL_PROJECT_ID => project.id,
              **payload
            )
          )
        end
      end
    end
  end
end
