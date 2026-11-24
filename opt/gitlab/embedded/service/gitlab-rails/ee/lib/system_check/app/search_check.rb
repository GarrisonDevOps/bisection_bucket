# frozen_string_literal: true

module SystemCheck
  module App
    class SearchCheck < SystemCheck::BaseCheck
      extend Gitlab::Utils::StrongMemoize

      set_name 'Elasticsearch version 7.x-9.x or OpenSearch version 1.x-3.x (9.x recommended for production)'
      set_skip_reason 'skipped (advanced search is disabled)'
      set_check_pass -> { "yes (#{distribution} #{current_version})" }
      set_check_fail -> { "no (#{distribution} #{current_version})" }

      # Elasticsearch 9.x is the current production version on GitLab.com
      # Elasticsearch 7.x is deprecated and planned for removal in GitLab 19.1
      ELASTICSEARCH_MAJOR_VERSIONS = 7..9
      OPENSEARCH_MAJOR_VERSIONS = 1..3

      def self.info
        strong_memoize(:info) do
          Search::Elastic::Helper.default.server_info
        end
      end

      def self.distribution
        info[:distribution]
      end

      def self.current_version
        Gitlab::VersionInfo.parse(info[:version])
      end

      def skip?
        !Gitlab::CurrentSettings.current_application_settings.elasticsearch_indexing?
      end

      def check?
        valid_elasticsearch_version? || valid_opensearch_version?
      end

      def show_error
        for_more_information(
          'doc/integration/advanced_search/elasticsearch.md'
        )
      end

      private

      def valid_elasticsearch_version?
        elasticsearch? && current_version.major.in?(ELASTICSEARCH_MAJOR_VERSIONS)
      end

      def valid_opensearch_version?
        opensearch? && current_version.major.in?(OPENSEARCH_MAJOR_VERSIONS)
      end

      def current_version
        self.class.current_version
      end

      def elasticsearch?
        self.class.distribution == 'elasticsearch'
      end

      def opensearch?
        self.class.distribution == 'opensearch'
      end
    end
  end
end
