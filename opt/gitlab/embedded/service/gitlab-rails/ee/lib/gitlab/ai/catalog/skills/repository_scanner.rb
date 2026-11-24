# frozen_string_literal: true

module Gitlab
  module Ai
    module Catalog
      module Skills
        # Reads the Skill files described by Path from a project's default branch and turns each
        # one into a Skill or a list of Rejections.
        #
        # Modelled on Gitlab::DuoWorkflow::WorkspaceAgentsReader, which does the same job for
        # `.agents/agents/*.md`. Lists the skills directory one level deep rather than searching
        # the repository, because Gitaly's path search walks every file in the tree: a project with
        # no skills would do the most work and find nothing, on every default-branch push.
        #
        # Callers must be able to tell "found nothing" apart from "could not see everything",
        # because an absent path is what licenses deleting a Catalog Item (ADR 0001):
        # - `scan` returns nil when the repository could not be read.
        # - ScanResult#truncated? is true when at least one matching file was not read.
        # In both cases a caller must reconcile no deletions. A path in `rejections` exists in the
        # repository; it is invalid, not absent.
        class RepositoryScanner
          include ::Gitlab::Loggable

          # A bound on how many skill directories one scan handles, not a product limit on how many
          # skills a project may have. Exceeding it marks the scan truncated, which suppresses
          # deletions rather than losing anything, so the value is safe to tune.
          MAX_SKILLS = 1_000

          # A bound on the blob data one scan holds, not a rule about how long a skill may be. Up
          # to MAX_SKILLS blobs are read at once, so this caps a scan at roughly 62 MiB where
          # Gitaly's 10 MiB default would allow nearly 10 GiB. The specification recommends
          # SKILL.md stay under 500 lines, so nothing conformant comes close to the per-file limit.
          MAX_READ_BYTES = 64.kilobytes

          # A bound on log line size when many paths are reported at once.
          MAX_LOGGED_PATHS = 10

          # The specification has no visibility field, so it lives in the `metadata` map it
          # provides for extensions, keeping it in git rather than as a mutable catalog-side field.
          #
          # Only the namespaced key is read. A bare `visibility` is exactly the key another tool
          # would reach for, and publishing a skill the author never meant to share is the one
          # mistake here that cannot be taken back.
          VISIBILITY_KEY = 'gitlab.visibility'
          VISIBILITIES = ::Ai::Catalog::Item.visibilities.keys.freeze
          DEFAULT_VISIBILITY = 'private'

          Skill = Data.define(
            :path, :name, :description, :blob_sha, :visibility, :license, :compatibility, :allowed_tools
          )

          ScanResult = Data.define(:skills, :rejections, :truncated) do
            alias_method :truncated?, :truncated
          end

          # @param project [Project]
          def initialize(project)
            @project = project
          end

          # @return [ScanResult, nil] nil when the repository could not be read and the result is unknown
          def scan
            sha = default_branch_sha

            unless sha
              log(message: 'Default branch did not resolve to a commit, skills were not scanned')
              return
            end

            blobs, truncated = read_skill_files(sha)
            skills, rejections = evaluate(blobs)

            ScanResult.new(skills: skills, rejections: rejections, truncated: truncated)
          # Broad on purpose: one unreadable repository should not fail the caller's worker, and nil
          # is the safe answer because it suppresses deletions.
          rescue StandardError => e
            ::Gitlab::ErrorTracking.track_exception(e, project_id: project.id)
            nil
          end

          private

          attr_reader :project

          # Pinned to one commit so both reads see the same tree. A branch name that resolves to
          # nothing would otherwise search nothing, and look exactly like a project with no skills.
          # Qualified because a bare name resolves to a tag of the same name first.
          def default_branch_sha
            branch = project.default_branch
            return unless branch

            project.repository.commit("#{::Gitlab::Git::BRANCH_REF_PREFIX}#{branch}")&.sha
          end

          # @return [Array(Array<Blob>, Boolean)] the blobs read, and whether any matching file was left unread
          def read_skill_files(sha)
            directories = skill_directories(sha)
            ignored_directories = directories.drop(MAX_SKILLS)
            candidates = directories.first(MAX_SKILLS).map { |directory| File.join(directory, Path::FILENAME) }

            paths = existing_paths(sha, candidates)
            blobs = project.repository.blobs_at(
              paths.map { |path| [sha, path] },
              blob_size_limit: MAX_READ_BYTES
            )

            # `blobs_at` silently omits a path it could not read. Such a path was never read, so it
            # must not be mistaken for a removed file.
            unread_paths = paths - blobs.map(&:path)

            log_over_limit(ignored_directories) if ignored_directories.any?
            log_unread(unread_paths) if unread_paths.any?

            [blobs, ignored_directories.any? || unread_paths.any?]
          end

          # One level deep, so a skill's own files -- references, scripts, assets -- are never
          # listed. A recursive listing would return all of them, and Gitaly applies no limit to a
          # recursive request, so its cost would grow with the contents of the skills rather than
          # with their number.
          #
          # Returned in tree order, so the subset kept when over the limit is the same every scan.
          def skill_directories(sha)
            project.repository.tree(sha, Path::ROOT).trees.map(&:path)
          end

          # SKILL.md is constructed from a directory name rather than discovered, so a directory
          # that holds no SKILL.md has to be told apart from one whose SKILL.md could not be read:
          # the first is simply not a skill, while the second must mark the scan truncated. Asking
          # for the type of each path draws that line before anything is read. One byte of content
          # is requested because only the type is wanted.
          def existing_paths(sha, candidates)
            return [] if candidates.empty?

            types = project.repository.get_blob_types(candidates.map { |path| [sha, path] }, 1)

            candidates.select { |path| types[path] == :blob }
          end

          # @return [Array(Array<Skill>, Array<Validator::Rejection>)]
          def evaluate(blobs)
            skills = []
            rejections = []

            blobs.each do |blob|
              blob_rejection = BlobCheck.rejection_for(blob)
              next rejections << blob_rejection if blob_rejection

              result = Validator.execute(path: blob.path, content: blob.data)

              if result.valid?
                skills << build_skill(blob, result.attributes)
              else
                rejections.concat(result.rejections)
              end
            end

            rejections.each { |rejection| log_rejection(rejection) }
            [skills, rejections]
          end

          def build_skill(blob, attributes)
            Skill.new(
              path: blob.path,
              name: attributes['name'],
              description: attributes['description'],
              blob_sha: blob.id,
              visibility: visibility(attributes['metadata'], blob.path),
              license: attributes['license'],
              compatibility: attributes['compatibility'],
              allowed_tools: attributes['allowed_tools']
            )
          end

          # An unrecognised value means private rather than a dropped skill: a typo in an optional
          # field should not remove the whole item, and the least visible option cannot leak.
          def visibility(metadata, path)
            value = metadata[VISIBILITY_KEY].to_s.strip.downcase
            return DEFAULT_VISIBILITY if value.empty?
            return value if VISIBILITIES.include?(value)

            log_unknown_visibility(path, value)
            DEFAULT_VISIBILITY
          end

          def log_rejection(rejection)
            log(
              message: 'Rejected skill file',
              path: rejection.path,
              category: rejection.category.to_s,
              Labkit::Fields::ADDITIONAL_DETAILS => rejection.message
            )
          end

          def log_over_limit(directories)
            log(
              message: 'Skill directories over the scan limit were not read',
              limit: MAX_SKILLS,
              ignored_count: directories.size,
              sample_paths: directories.first(MAX_LOGGED_PATHS)
            )
          end

          def log_unread(paths)
            log(
              message: 'Skill files found by search could not be read',
              unread_count: paths.size,
              sample_paths: paths.first(MAX_LOGGED_PATHS)
            )
          end

          def log_unknown_visibility(path, value)
            log(
              message: 'Unknown skill visibility, defaulting to private',
              path: path,
              Labkit::Fields::ADDITIONAL_DETAILS => value
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
end
