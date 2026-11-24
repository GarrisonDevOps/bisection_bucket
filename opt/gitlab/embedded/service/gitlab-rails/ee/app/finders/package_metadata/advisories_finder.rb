# frozen_string_literal: true

# rubocop: disable Gitlab/BoundedContexts -- this namespace is already established, embedding it deeper into another namespace would make things inconsistent.
module PackageMetadata
  class AdvisoriesFinder
    def initialize(params = {})
      raise ArgumentError, 'identifiers argument is missing' if params[:identifiers].blank?

      @params = params
    end

    def execute
      advisories = base_query
      advisories = by_identifiers(advisories)
      advisories = by_created_after(advisories)
      by_updated_after(advisories)
    end

    private

    attr_reader :params

    def base_query
      ::PackageMetadata::Advisory.ordered_by_id
    end

    def by_identifiers(advisories)
      advisories.by_identifiers(params[:identifiers])
    end

    def by_created_after(advisories)
      return advisories unless params[:created_after].present?

      advisories.created_after(params[:created_after])
    end

    def by_updated_after(advisories)
      return advisories unless params[:updated_after].present?

      advisories.updated_after(params[:updated_after])
    end
  end
end
# rubocop: enable Gitlab/BoundedContexts
