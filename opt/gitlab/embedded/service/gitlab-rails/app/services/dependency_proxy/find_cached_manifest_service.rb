# frozen_string_literal: true

module DependencyProxy
  class FindCachedManifestService < DependencyProxy::BaseService
    def initialize(group, image, tag, token)
      @group = group
      @image = image
      @tag = tag
      @token = token
      @file_name = "#{@image}:#{@tag}.json"
      @manifest = nil
    end

    def execute
      @manifest = @group.dependency_proxy_manifests
                        .active
                        .find_by_file_name_or_digest(file_name: @file_name, digest: @tag)

      head_result = DependencyProxy::HeadManifestService.new(@image, @tag, @token).execute

      return respond if cached_manifest_matches?(head_result)
      return respond if @manifest && head_result[:status] == :error

      success(manifest: nil, from_cache: false)
    end

    private

    def cached_manifest_matches?(head_result)
      return false if head_result[:status] == :error

      @manifest && @manifest.digest == head_result[:digest] && @manifest.content_type == head_result[:content_type]
    end

    def respond(from_cache: true)
      @manifest.read!

      success(manifest: @manifest, from_cache: from_cache)
    end
  end
end
