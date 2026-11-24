# frozen_string_literal: true

module Autocomplete
  class VulnerabilitiesAutocompleteFinder
    attr_reader :current_user, :vulnerable, :params

    # current_user - the User object of the user that wants to view the list of Vulnerabilities
    #
    # vulnerable - any object that has a #vulnerabilities method that returns a collection of vulnerabilitie
    # params - a Hash containing additional parameters to set
    #
    # The supported parameters are those supported by
    # `Security::VulnerabilityReadsFinder`.
    def initialize(current_user, vulnerable, params = {})
      @current_user = current_user
      @vulnerable = vulnerable
      @params = params
    end

    DEFAULT_AUTOCOMPLETE_LIMIT = 5

    def execute
      return ::Vulnerability.none unless current_user && vulnerable.feature_available?(:security_dashboard)

      if vulnerable.is_a?(Group)
        group_vulnerabilities
      else
        project_vulnerabilities
      end
    end

    # Due to the Sec decomposition, it is not possible to simply perform a full joined query to extract a
    # set of vulnerabilities for a namespace hierarchy that honours project authorizations to exclude unpermitted
    # projects.
    #
    # Additionally, large `IN` clauses can cause performance concerns. As such, the below operation needs to:
    # 1. Query the set of authorized projects (that contain vulnerabilities) from the desired namespace hierarchy
    # 2. Query Vulnerability::Reads using the same namespace hierarchy, but then apply the batch of project_ids from
    # the first query as a tighter scope. This prevents us from reading unpermitted projects in the hierarchy.
    #
    # While needing to execute this query in batches is not ideal, the combination of traversal_id and project_id
    # scoping on vulnerability_reads should be well indexed and quick to respond if there are no results.
    # If there are DEFAULT_AUTOCOMPLETE_LIMIT many results, then we can escape early.
    #
    # There are known performance concerns relating to the way this works due to the sheer possible scale of
    # vulnerabilities that may need to be read if no autocomplete results are found. This will need to be improved
    # in further iterations. For more context, see:
    # https://gitlab.com/gitlab-org/gitlab/-/merge_requests/175947#note_2289221607

    PROJECT_BATCH_SIZE = 10
    private_constant :PROJECT_BATCH_SIZE

    def group_vulnerabilities
      result = ::Vulnerability.none

      vulnerable.all_projects
                .has_vulnerabilities
                .visible_to_user_and_access_level(current_user, ::Gitlab::Access::DEVELOPER)
                .each_batch(of: PROJECT_BATCH_SIZE) do |projects|
        result += ::Security::VulnerabilityReadsFinder # rubocop: disable CodeReuse/Finder
                    .new(vulnerable, project_id: projects.pluck_primary_key)
                    .execute
                    .autocomplete_search(params[:search].to_s)
                    .with_limit(DEFAULT_AUTOCOMPLETE_LIMIT)
                    .order_id_desc
                    .as_vulnerabilities

        break if result.length >= DEFAULT_AUTOCOMPLETE_LIMIT
      end

      # Each batch contributes up to the limit, so the accumulated result can
      # exceed it. The project branch is already capped by its single query.
      result.first(DEFAULT_AUTOCOMPLETE_LIMIT)
    end

    def project_vulnerabilities
      return ::Vulnerability.none unless current_user.authorized_project?(vulnerable, Gitlab::Access::DEVELOPER)

      ::Security::VulnerabilityReadsFinder # rubocop: disable CodeReuse/Finder
        .new(vulnerable)
        .execute
        .autocomplete_search(params[:search].to_s)
        .with_limit(DEFAULT_AUTOCOMPLETE_LIMIT)
        .order_id_desc
        .as_vulnerabilities
    end
  end
end
