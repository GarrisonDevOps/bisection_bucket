#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative '../../config/environment'
require_relative '../../keeps/helpers/gitlab_api_helper'

module FeatureFlags
  # Posts one note on the tracking issue listing the merge requests the feature flag removal keep
  # opened recently, so the MRs stay visible without anyone writing the note by hand.
  #
  # Meant to run after the housekeeper job in the same scheduled pipeline; that CI job lives with
  # the scheduled-pipeline configuration and is added separately from this script. Run by hand with:
  #
  # ```
  # bundle exec ruby scripts/feature_flags/post_removal_mr_digest.rb
  # ```
  class PostRemovalMrDigest
    SOURCE_PROJECT = 'gitlab-org/gitlab'
    TRACKING_ISSUE_URL =
      'https://gitlab.com/gitlab-org/quality/engineering-productivity/team/-/work_items/597'
    LABEL = 'automation:feature-flag-removal'
    DEFAULT_LOOKBACK_DAYS = 7
    API_HOST = 'https://gitlab.com/api/v4'
    # The lookahead rejects group-level work item URLs (/groups/<group>/-/work_items/<iid>): those
    # have no project to build a projects API path from, and would otherwise 404 confusingly.
    ISSUE_URL_REGEX = %r{\Ahttps://gitlab\.com/(?!groups/)(?<project_path>.+)/-/(?:issues|work_items)/(?<iid>\d+)\z}

    Error = Class.new(StandardError)

    def initialize(logger: $stdout)
      @logger = logger
    end

    def execute
      merge_requests = recent_merge_requests

      if merge_requests.empty?
        logger.puts "No merge requests labelled #{LABEL} in the last #{lookback_days} days."
        return
      end

      new_merge_requests = merge_requests.reject { |mr| already_noted?(mr['web_url']) }

      if new_merge_requests.empty?
        logger.puts "All #{merge_requests.size} merge requests are already noted on #{tracking_issue_url}."
        return
      end

      post_note(new_merge_requests)
    end

    private

    attr_reader :logger

    def tracking_issue_url
      ENV.fetch('FEATURE_FLAG_REMOVAL_TRACKING_ISSUE_URL', TRACKING_ISSUE_URL)
    end

    # A malformed env value parses to 0, which would look back to now and report nothing;
    # fall back to the default window instead.
    def lookback_days
      days = ENV.fetch('FEATURE_FLAG_REMOVAL_LOOKBACK_DAYS', DEFAULT_LOOKBACK_DAYS).to_i
      days > 0 ? days : DEFAULT_LOOKBACK_DAYS
    end

    # Deliberately unfiltered by state: the note records what the keep opened, and an MR that was
    # merged or closed inside the window still needs to appear once.
    def recent_merge_requests
      created_after = lookback_days.days.ago.utc.iso8601
      url = "#{API_HOST}/projects/#{CGI.escape(SOURCE_PROJECT)}/merge_requests" \
        "?labels=#{CGI.escape(LABEL)}&created_after=#{created_after}&per_page=100"

      merge_requests = []
      api_helper.query_api(url) { |mr| merge_requests << mr }
      merge_requests
    end

    # The job can be retried, so never post an MR that an earlier run already listed. Anchor the
    # match so `/merge_requests/1` is not treated as noted just because `/merge_requests/12` is.
    def already_noted?(mr_url)
      pattern = /#{Regexp.escape(mr_url)}(?!\d)/
      existing_note_bodies.any? { |body| body.match?(pattern) }
    end

    def existing_note_bodies
      @existing_note_bodies ||= begin
        bodies = []
        api_helper.query_api("#{issue_api_url}/notes?per_page=100") { |note| bodies << note['body'].to_s }
        bodies
      end
    end

    def post_note(merge_requests)
      response = api_helper.post("#{issue_api_url}/notes", { body: note_body(merge_requests) })

      raise Error, "Failed to post note: #{response.code} #{response.body}" unless response.success?

      logger.puts "Posted a note listing #{merge_requests.size} merge requests on #{tracking_issue_url}."
    end

    def note_body(merge_requests)
      lines = merge_requests.map { |mr| "- #{mr['web_url']} — #{mr['title']}" }

      <<~MARKDOWN
        The automated feature flag removal opened #{merge_requests.size} #{'merge request'.pluralize(merge_requests.size)} in the last #{lookback_days} days:

        #{lines.join("\n")}

        Posted by `scripts/feature_flags/post_removal_mr_digest.rb`.
      MARKDOWN
    end

    def issue_api_url
      matches = ISSUE_URL_REGEX.match(tracking_issue_url)

      unless matches
        raise Error,
          "Cannot parse tracking issue URL (must be a project-level issue or work item): #{tracking_issue_url}"
      end

      "#{API_HOST}/projects/#{CGI.escape(matches[:project_path])}/issues/#{matches[:iid]}"
    end

    # Posting on the tracking issue needs write access to a different project than the keeps read
    # from, so this takes its own token rather than the QA-scoped default.
    def api_helper
      @api_helper ||= ::Keeps::Helpers::GitlabApiHelper.new(
        token: ENV['FEATURE_FLAG_REMOVAL_API_TOKEN'] || ENV['HOUSEKEEPER_GITLAB_API_TOKEN']
      )
    end
  end
end

FeatureFlags::PostRemovalMrDigest.new.execute if $PROGRAM_NAME == __FILE__
