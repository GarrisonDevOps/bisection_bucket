# frozen_string_literal: true

module Dast
  class ProfilesFinder
    DEFAULT_SORT = { id: :desc }.freeze

    def initialize(params = {})
      @params = params
    end

    def execute
      relation = default_relation
      relation = by_id(relation)
      relation = by_project(relation)
      relation = has_schedule?(relation)
      relation = by_site_profile_id(relation)
      relation = by_scanner_profile_id(relation)
      relation = with_project(relation)

      sort(relation)
    end

    private

    attr_reader :params

    def default_relation
      Dast::Profile.limit(100).with_schedule_owner
    end

    def by_id(relation)
      return relation if params[:id].nil?

      relation.id_in(params[:id])
    end

    def by_project(relation)
      return relation if params[:project_id].nil?

      relation.by_project_id(params[:project_id])
    end

    def has_schedule?(relation)
      return relation if params[:has_dast_profile_schedule].nil?

      relation.with_schedule(params[:has_dast_profile_schedule])
    end

    def by_site_profile_id(relation)
      return relation if params[:site_profile_id].nil?

      relation.by_site_profile_id(params[:site_profile_id])
    end

    def by_scanner_profile_id(relation)
      return relation if params[:scanner_profile_id].nil?

      relation.by_scanner_profile_id(params[:scanner_profile_id])
    end

    def with_project(relation)
      return relation unless params[:with_project]

      relation.with_project
    end

    # rubocop: disable CodeReuse/ActiveRecord
    def sort(relation)
      relation.order(DEFAULT_SORT)
    end
    # rubocop: enable CodeReuse/ActiveRecord
  end
end
