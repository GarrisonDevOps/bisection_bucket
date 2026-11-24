# frozen_string_literal: true

module EE
  module SearchController
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    class_methods do
      extend ::Gitlab::Utils::Override

      override :search_rate_limited_endpoints
      def search_rate_limited_endpoints
        super.push(:aggregations)
      end
    end

    prepended do
      track_event :show,
        name: 'i_search_advanced',
        conditions: -> { track_search_advanced? },
        label: 'redis_hll_counters.search.search_total_unique_counts_monthly',
        action: 'executed',
        destinations: %i[redis_hll snowplow]

      track_event :autocomplete,
        name: 'i_search_advanced',
        conditions: -> { track_search_advanced? },
        label: 'redis_hll_counters.search.search_total_unique_counts_monthly',
        action: 'autocomplete',
        destinations: %i[redis_hll snowplow]

      track_event :show,
        name: 'i_search_paid',
        conditions: -> { track_search_paid? },
        label: 'redis_hll_counters.search.i_search_paid_monthly',
        action: 'executed',
        destinations: %i[redis_hll snowplow]

      track_event :autocomplete,
        name: 'i_search_paid',
        conditions: -> { track_search_paid? },
        label: 'redis_hll_counters.search.i_search_paid_monthly',
        action: 'autocomplete',
        destinations: %i[redis_hll snowplow]

      rescue_from Elastic::TimeoutError, with: :render_timeout

      before_action :check_search_rate_limit!, only: search_rate_limited_endpoints
      before_action :sso_enforcement_redirect, only: [:show]
      after_action :run_index_integrity_worker, only: :show, if: :no_results_for_group_or_project_blobs_advanced_search?
      after_action :track_exact_code_search, only: :show, if: :track_search_zoekt?
    end

    def aggregations
      params.require(:search)

      @scope = search_service.scope
      @search_type = search_type
      @search_level = search_service.level

      if search_term_valid?
        # Cache the response on the frontend
        cache_for = ::Gitlab::Saas.feature_available?(:advanced_search) ? 5.minutes : 1.minute
        expires_in cache_for

        result = nil
        @search_attempted = true
        @global_search_duration_s = Benchmark.realtime do
          result = search_service.search_aggregations.to_json
        end

        render json: result

        record_search_apdex(observe_duration: false)
      else
        render json: { error: flash[:alert] }, status: :bad_request
      end
    rescue ::Gitlab::Search::Client::ConnectionError, ::Gitlab::Search::Client::AuthorizationError => e
      ::Gitlab::ErrorTracking.log_exception(e, class: self.class.name)

      error_type = e.class.name.demodulize.underscore

      render json: {
        error: e.message,
        error_type: error_type
      }, status: :service_unavailable
    rescue ::Search::Zoekt::Errors::BaseError => e
      ::Gitlab::ErrorTracking.log_exception(e, class: self.class.name)

      error_type = e.class.name.demodulize.underscore

      # Unlike the Elasticsearch client errors above, these carry raw backend detail -- a
      # transport failure naming the node URL, or a namespace and replica -- so the message
      # must not be echoed back to the client.
      render json: {
        error: 'Search is currently unavailable. Please try again later.',
        error_type: error_type
      }, status: :service_unavailable
    ensure
      record_search_error
    end

    override :autocomplete
    def autocomplete
      super
    rescue ::Gitlab::Search::Client::ConnectionError, ::Gitlab::Search::Client::AuthorizationError => e
      ::Gitlab::ErrorTracking.log_exception(e, class: self.class.name)

      render json: ::Gitlab::Json.dump([])
    end

    override :count
    def count
      super
    rescue ::Gitlab::Search::Client::ConnectionError, ::Gitlab::Search::Client::AuthorizationError => e
      ::Gitlab::ErrorTracking.log_exception(e, class: self.class.name)

      render json: {}, status: :service_unavailable
    end

    private

    override :multi_match?
    def multi_match?(search_type:, scope:)
      scope == 'blobs' && search_type == 'zoekt'
    end

    override :default_sort
    def default_sort
      if search_service.use_elasticsearch?
        'relevant'
      else
        super
      end
    end

    def track_search_advanced?
      search_type == 'advanced' && search_service.use_elasticsearch?
    end

    def track_search_zoekt?
      search_type == 'zoekt' && search_service.use_zoekt?
    end

    def track_search_paid?
      track_search_advanced? || track_search_zoekt?
    end

    def no_results_for_group_or_project_blobs_advanced_search?
      return false unless search_service.scope == 'blobs'
      return false unless search_service.project || search_service.group
      return false unless search_type == 'advanced'
      return false if search_service.abuse_detected?
      return false if @search_results.nil? || @search_results.failed?(search_service.scope)

      search_service.search_objects.blank?
    end

    def run_index_integrity_worker
      resource = search_service.project || search_service.group

      resource_scope = ::Gitlab::ApplicationRateLimiter.parent_scope(resource)

      return if ::Gitlab::ApplicationRateLimiter.throttled?(:search_index_integrity, scope: resource_scope)

      if search_service.project.present?
        ::Search::ProjectIndexIntegrityWorker.perform_async(search_service.project.id)
      else
        ::Search::NamespaceIndexIntegrityWorker.perform_async(search_service.group.id)
      end
    end

    override :search_params
    # Keep doc/user/search/advanced_search.md in sync: it documents this
    # permitted set as the canonical list of merge request search filters.
    def search_params
      super.merge(params.permit(
        :source_branch, :target_branch, :author_username,
        :created_after, :created_before, :updated_after, :updated_before,
        assignee_ids: [],
        not: [:source_branch, :target_branch, :author_username, { assignee_ids: [] }]
      ))
    end

    override :search_payload_metadata
    def search_payload_metadata
      super.merge(
        'meta.search.filters.source_branch' => search_params[:source_branch],
        'meta.search.filters.not_source_branch' => search_params.dig(:not, :source_branch),
        'meta.search.filters.target_branch' => search_params[:target_branch],
        'meta.search.filters.not_target_branch' => search_params.dig(:not, :target_branch),
        'meta.search.filters.author_username' => search_params[:author_username],
        'meta.search.filters.not_author_username' => search_params.dig(:not, :author_username),
        'meta.search.filters.assignee_ids' => search_params[:assignee_ids],
        'meta.search.filters.not_assignee_ids' => search_params.dig(:not, :assignee_ids),
        'meta.search.filters.created_after' => search_params[:created_after],
        'meta.search.filters.created_before' => search_params[:created_before],
        'meta.search.filters.updated_after' => search_params[:updated_after],
        'meta.search.filters.updated_before' => search_params[:updated_before]
      )
    end

    def sso_enforcement_redirect
      # redirection should occur for group searches only
      return unless search_service.level.to_sym == :group

      search_group = search_service.group
      return unless search_group

      params = { user: current_user, resource: search_group, skip_owner_check: true }
      redirect = ::Gitlab::Auth::GroupSaml::SsoEnforcer.access_restricted?(**params)
      return unless redirect

      redirect_to sso_group_saml_providers_url(search_group.root_ancestor, { redirect: request.fullpath })
    end

    def track_exact_code_search
      track_internal_event('search_exact_code', user: current_user)
    end

    override :haml_search_results
    def haml_search_results
      super

    rescue ::Gitlab::Search::Client::ConnectionError, ::Gitlab::Search::Client::AuthorizationError => e
      ::Gitlab::ErrorTracking.log_exception(e, class: self.class.name)

      error_type = e.class.name.demodulize.underscore
      @search_results = ::Search::EmptySearchResults.new(error: e.message, error_type: error_type)
    end
  end
end
