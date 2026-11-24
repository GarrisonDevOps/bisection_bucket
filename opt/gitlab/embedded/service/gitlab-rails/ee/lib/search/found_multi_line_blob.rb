# frozen_string_literal: true

module Search
  class FoundMultiLineBlob
    include BlobActiveModel

    attr_reader :blame_url, :chunks, :file_url, :language,
      :match_count, :match_count_total, :path, :project_path, :project

    def initialize(opts = {})
      @path = opts[:path]
      @chunks = opts[:chunks]
      @file_url = opts[:file_url]
      @blame_url = opts[:blame_url]
      @match_count_total = opts[:match_count_total]
      @match_count = opts[:match_count]
      @project_path = opts[:project_path]
      @project = opts[:project]
      @language = opts[:language]
    end

    def id
      nil
    end
  end
end
