# frozen_string_literal: true

module Search
  module AdvancedAndZoektSearchable
    include ::Search::Elasticsearchable
    include ::Search::ZoektSearchable

    def execute
      case search_type
      when 'zoekt'
        zoekt_search_results
      when 'advanced'
        elasticsearch_results
      else
        super
      end
    end

    def search_type
      return params[:search_type] if params[:search_type]

      if scope == 'blobs'
        return 'zoekt' if use_zoekt?
        return 'advanced' if Gitlab::CurrentSettings.elasticsearch_code_scope && use_elasticsearch?
      elsif use_elasticsearch?
        return 'advanced'
      end

      'basic'
    end
  end
end
