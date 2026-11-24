#!/usr/bin/env ruby
# frozen_string_literal: true

# Checks that the HTTP Router's committed routing snapshot has every route this
# branch adds or changes.
#
# GitLab owns config/routing/gitlab_routes.json. The HTTP Router mirrors it at
# test/routes/gitlab_routes.json and replays every example against its own
# routing table, so a route GitLab knows about and the router does not can be
# classified to the wrong cell.
#
# Only the routes that differ from the snapshot on the target branch must be in
# the router. Requiring the whole file to match forced route changes from
# different merge requests to merge one at a time.
#
# Exit codes are distinct so CI can treat a download problem differently from
# real drift:
#
#   0  in sync
#   1  the router does not have a route this branch adds or changes
#   2  a snapshot could not be downloaded, or was not a snapshot
#
# The snapshots are read through the Repository Files API rather than /-/raw,
# whose unauthenticated rate limit is low enough to fail the job under load.
# In CI the requests carry CI_JOB_TOKEN so they count as authenticated.
#
# Overridable for local runs and fork branches:
#
#   CELLS_ROUTER_PROJECT       default gitlab-org/cells/http-router
#   CELLS_ROUTER_REF           default main
#   CELLS_ROUTER_SNAPSHOT_URL  bypasses both of the above
#   CELLS_ROUTES_BASE_REF      default CI_MERGE_REQUEST_TARGET_BRANCH_SHA, then
#                              CI_MERGE_REQUEST_DIFF_BASE_SHA, then master. On a
#                              local run of an old branch, set it to
#                              $(git merge-base HEAD origin/master).
#   CELLS_ROUTES_BASE_URL      bypasses the base ref and project
#   CI_API_V4_URL              default https://gitlab.com/api/v4
#
# Runs on plain Ruby with no bundle: the gem it loads has no runtime
# dependencies, so the CI job needs no gems and can run with `needs: []`.

require "cgi"
require "net/http"
require "openssl"
require "uri"

require_relative "../../gems/gitlab-cells-http_router/lib/gitlab/cells/http_router"

module CheckRouterRoutesSync
  RouterSnapshot = Gitlab::Cells::HttpRouter::RouterSnapshot
  BaseSnapshot = Gitlab::Cells::HttpRouter::BaseSnapshot
  SnapshotComparison = Gitlab::Cells::HttpRouter::SnapshotComparison

  LOCAL_SNAPSHOT = "config/routing/gitlab_routes.json"
  DOCS_URL = "https://docs.gitlab.com/development/cells/http_router/#check-the-http-router-is-in-sync"
  ROUTER_DOCS_URL = "https://gitlab.com/gitlab-org/cells/http-router/-/blob/main/docs/adding-gitlab-routes.md"

  MAX_LISTED_TEMPLATES = 20
  OPEN_TIMEOUT = 10
  READ_TIMEOUT = 60
  MAX_ATTEMPTS = 3

  IN_SYNC = 0
  DRIFT = 1
  DOWNLOAD_FAILED = 2

  # Worth retrying: a transport error or a 5xx. A 404 is a wrong ref, which
  # retrying cannot fix, so it raises DownloadError directly.
  DownloadError = Class.new(StandardError)
  RetryableDownloadError = Class.new(DownloadError)

  TRANSPORT_ERRORS = [
    Timeout::Error, SystemCallError, SocketError, Net::HTTPBadResponse, OpenSSL::SSL::SSLError
  ].freeze

  class << self
    def run
      local_payload = read_local_snapshot
      return report_missing_local unless local_payload

      comparison = SnapshotComparison.new(
        gitlab_payload: local_payload,
        base_payload: download(base_snapshot_url),
        router_payload: download(snapshot_url)
      )

      return report_in_sync if comparison.in_sync?

      report_drift(comparison)
      DRIFT
    rescue SnapshotComparison::InvalidSnapshotError => e
      warn "cells-routes: #{e.message}"
      e.source == :gitlab ? report_invalid_local : report_download_failed
    rescue DownloadError => e
      warn "cells-routes: #{e.message}"
      report_download_failed
    end

    private

    def repo_root
      @repo_root ||= File.expand_path("../..", __dir__)
    end

    def local_path
      File.join(repo_root, LOCAL_SNAPSHOT)
    end

    # Rescues here, not around run: a stray ENOENT from anywhere else must not
    # read as a missing snapshot.
    def read_local_snapshot
      File.read(local_path)
    rescue Errno::ENOENT
      nil
    end

    def snapshot_url
      @snapshot_url ||= RouterSnapshot.url_from_env
    end

    def base_snapshot_url
      @base_snapshot_url ||= BaseSnapshot.url_from_env
    end

    def download(url)
      attempt = 0

      begin
        attempt += 1
        fetch(URI.parse(url))
      rescue RetryableDownloadError, *TRANSPORT_ERRORS => e
        raise DownloadError, "could not download #{url}: #{e.message}" if attempt >= MAX_ATTEMPTS

        sleep(attempt)
        retry
      end
    end

    def fetch(uri)
      response = Net::HTTP.start(
        uri.host, uri.port,
        use_ssl: uri.scheme == "https",
        open_timeout: OPEN_TIMEOUT,
        read_timeout: READ_TIMEOUT
      ) { |http| http.request(build_request(uri)) }

      case response
      when Net::HTTPSuccess
        response.body
      when Net::HTTPServerError
        raise RetryableDownloadError, "#{uri} returned HTTP #{response.code}"
      else
        raise DownloadError, "#{uri} returned HTTP #{response.code} #{response.message}"
      end
    end

    def build_request(uri)
      request = Net::HTTP::Get.new(uri)
      token = RouterSnapshot.job_token
      request["JOB-TOKEN"] = token if token
      request
    end

    def report_in_sync
      puts "cells-routes: HTTP Router snapshot: #{snapshot_url}"
      puts "cells-routes: target branch snapshot: #{base_snapshot_url}"
      puts "cells-routes: the HTTP Router has every route that this branch adds or changes."
      IN_SYNC
    end

    def report_missing_local
      warn "cells-routes: #{LOCAL_SNAPSHOT} does not exist."
      warn "cells-routes: run 'bundle exec rake gitlab:cells:routes:generate' and commit the result."
      DRIFT
    end

    def report_invalid_local
      warn <<~MESSAGE

        The problem is #{LOCAL_SNAPSHOT} on this branch, not the download. It is not a
        routing snapshot, so nothing was compared. Run
        'bundle exec rake gitlab:cells:routes:generate' and commit the result.
      MESSAGE

      DRIFT
    end

    def report_download_failed
      warn <<~MESSAGE

        DOWNLOAD FAILED - this is not route drift.

        A routing snapshot could not be downloaded, or the downloaded file is not a valid
        snapshot, so nothing was compared. The message above names the file and the problem.
        If the download failed, retry the job. If the file is not valid, retrying does not
        help. Fix the file in its repository.
      MESSAGE

      DOWNLOAD_FAILED
    end

    def report_drift(comparison)
      warn "cells-routes: HTTP Router snapshot: #{snapshot_url}"
      warn "cells-routes: target branch snapshot: #{base_snapshot_url}"

      report_side(comparison.missing, "added or changed on this branch are not in the HTTP Router")
      report_side(comparison.outdated, "added or changed on this branch have different fields in the HTTP Router")

      warn drift_guidance
    end

    def report_side(templates, label)
      return if templates.empty?

      warn ""
      warn "#{templates.size} route templates #{label}:"
      templates.first(MAX_LISTED_TEMPLATES).each { |template| warn "  #{template}" }

      return unless templates.size > MAX_LISTED_TEMPLATES

      warn "  ... and #{templates.size - MAX_LISTED_TEMPLATES} more"
    end

    def drift_guidance
      <<~MESSAGE

        The HTTP Router's committed route snapshot does not have every route that this
        branch adds or changes. Routes that only the HTTP Router has do not cause this
        failure.

        Open a paired merge request in gitlab-org/cells/http-router that runs:
          npm run download-gitlab-routes -- <this-branch-name>
        Update the vitest snapshot, merge that request, then re-run this pipeline.

        Most new routes match an existing router rule and need only the refreshed
        snapshot. The step-by-step procedure, including how to tell that case apart
        from one that needs a routing change, is here:
          #{ROUTER_DOCS_URL}

        Docs: #{DOCS_URL}
      MESSAGE
    end
  end
end

exit CheckRouterRoutesSync.run if $PROGRAM_NAME == __FILE__
