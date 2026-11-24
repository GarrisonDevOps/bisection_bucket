# frozen_string_literal: true

require "cgi"

module Gitlab
  module Cells
    module HttpRouter
      # Locates GitLab's own routing snapshot on the merge request's target, so
      # a comparison can tell the routes a branch adds from the ones it inherits.
      module BaseSnapshot
        PROJECT = "gitlab-org/gitlab"
        PATH = "config/routing/gitlab_routes.json"
        DEFAULT_REF = "master"
        DEFAULT_API_URL = "https://gitlab.com/api/v4"

        # A merged results pipeline checks out the target branch tip merged with
        # the branch, so the merge-base would count routes merged since then as
        # this branch's own. CI_MERGE_REQUEST_TARGET_BRANCH_SHA is empty elsewhere.
        REF_VARIABLES = %w[
          CELLS_ROUTES_BASE_REF
          CI_MERGE_REQUEST_TARGET_BRANCH_SHA
          CI_MERGE_REQUEST_DIFF_BASE_SHA
        ].freeze

        def self.url(project: PROJECT, ref: DEFAULT_REF, api_url: DEFAULT_API_URL)
          format("%s/projects/%s/repository/files/%s/raw?ref=%s",
            api_url, CGI.escape(project), CGI.escape(PATH), CGI.escape(ref))
        end

        def self.url_from_env(env = ENV)
          env.fetch("CELLS_ROUTES_BASE_URL", nil) || url(
            project: env.fetch("CI_MERGE_REQUEST_PROJECT_PATH", PROJECT),
            ref: ref_from_env(env),
            api_url: env.fetch("CI_API_V4_URL", DEFAULT_API_URL)
          )
        end

        def self.ref_from_env(env = ENV)
          REF_VARIABLES.map { |name| env.fetch(name, nil).to_s }.find { |ref| !ref.empty? } || DEFAULT_REF
        end
      end
    end
  end
end
