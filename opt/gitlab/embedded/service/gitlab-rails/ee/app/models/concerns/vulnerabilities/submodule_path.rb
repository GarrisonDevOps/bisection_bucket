# frozen_string_literal: true

module Vulnerabilities
  module SubmodulePath
    extend ActiveSupport::Concern

    private

    # Resolves a vulnerability file path that may be inside a submodule.
    #
    # Security scanners report file paths relative to the parent project root where
    # they ran. When submodules are checked out (GIT_SUBMODULE_STRATEGY: recursive),
    # a file like "lib/my-submodule/src/file.rb" means the file at "src/file.rb"
    # inside the submodule mounted at "lib/my-submodule". The submodule mount path
    # is already embedded as a prefix in the scanner-reported path.
    #
    # Returns a full blob URL pointing to the file in the submodule's own project,
    # or nil if the file path does not match any known submodule.
    def resolve_submodule_blob_url(project, sha, file_path)
      return unless sha.present? && file_path.present?

      submodule_urls = cached_submodule_urls_for(project, sha)
      return unless submodule_urls.present?

      compute_submodule_blob_url(project, sha, file_path, submodule_urls)
    rescue Gitlab::Git::Repository::NoRepository, Gitlab::Git::CommandError
      nil
    end

    # Fetches submodule URL mappings for the given project+sha, caching the result
    # per request so that multiple findings on the same commit share a single Gitaly call.
    def cached_submodule_urls_for(project, sha)
      Gitlab::SafeRequestStore.fetch("submodule_urls:#{project.id}:#{sha}") do
        project.repository.submodule_urls_for(sha)
      end
    end

    def compute_submodule_blob_url(project, sha, file_path, submodule_urls)
      submodule_urls.each do |submodule_path, submodule_url|
        # The scanner path is relative to the parent project root, so a file inside
        # a submodule has the submodule mount path as a prefix. Use string matching
        # rather than blob_at existence checks -- the gitlink entry and .gitmodules
        # data are always present in the git tree regardless of submodule checkout.
        next unless file_path.start_with?("#{submodule_path}/")

        relative_file = file_path.delete_prefix("#{submodule_path}/")

        # The gitlink tree entry for the submodule directory holds the pinned commit OID.
        submodule_entry = project.repository.blob_at(sha, submodule_path)
        next unless submodule_entry

        submodule_commit_id = submodule_entry.id

        url = build_submodule_blob_url(submodule_url, submodule_commit_id, relative_file, project)
        return url if url
      end

      nil
    end

    def build_submodule_blob_url(submodule_url, submodule_commit_id, relative_file, project)
      # SubmoduleHelper.submodule_links_for_url returns [web_url, tree_url, compare_url].
      # tree_url points to the submodule's tree at the pinned commit SHA.
      _web_url, tree_url, _compare_url = SubmoduleHelper.submodule_links_for_url(
        submodule_commit_id, submodule_url, project.repository
      )

      return unless tree_url

      # tree_url examples:
      #   Same instance:  "/namespace/project/-/tree/<sha>"
      #   GitLab.com:     "https://gitlab.com/namespace/project/-/tree/<sha>"
      #   GitHub.com:     "https://github.com/namespace/project/tree/<sha>"
      #
      # Replace the tree segment with blob and append the relative file path.
      escaped_sha = Regexp.escape(submodule_commit_id)
      blob_url = tree_url
        .sub(%r{/-/tree/#{escaped_sha}\z}, "/-/blob/#{submodule_commit_id}/#{relative_file}")
        .sub(%r{/tree/#{escaped_sha}\z}, "/blob/#{submodule_commit_id}/#{relative_file}")

      # If neither substitution matched (e.g. GitHub Gist URLs have no /tree/ segment),
      # fall back to nil so the caller can use the parent project path instead.
      blob_url == tree_url ? nil : blob_url
    end
  end
end
