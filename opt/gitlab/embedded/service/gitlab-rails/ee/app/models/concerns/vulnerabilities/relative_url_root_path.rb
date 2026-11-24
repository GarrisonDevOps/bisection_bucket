# frozen_string_literal: true

module Vulnerabilities
  module RelativeUrlRootPath
    extend ActiveSupport::Concern

    private

    # Used by Vulnerabilities::FindingPresenter#blob_url and VulnerabilityPresenter#location_link
    # to turn a finding's location - which may point into a git submodule - into a portable URL.
    # Path helpers already embed relative_url_root, so appending onto root_url would duplicate it.
    # Submodule links come from SubmoduleHelper, built as relative hrefs for in-page browser
    # resolution; a policy bot-authored markdown comment has no such implicit base to resolve against.
    def absolutize_path(path)
      return path if %r{\Ahttps?://}i.match?(path)

      relative_path = path.delete_prefix(Gitlab.config.gitlab.relative_url_root.to_s)
      ::Gitlab::Utils.append_path(root_url, relative_path)
    end

    def root_url
      Gitlab::Routing.url_helpers.root_url
    end
  end
end
