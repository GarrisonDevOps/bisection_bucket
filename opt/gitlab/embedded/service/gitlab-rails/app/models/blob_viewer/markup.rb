# frozen_string_literal: true

module BlobViewer
  class Markup < Base
    include Rich
    include ServerSide

    self.partial_name = 'markup'
    self.extensions = Gitlab::MarkupHelper::EXTENSIONS
    self.file_types = %i[readme]
    self.binary = false

    def banzai_render_context
      {}.tap do |h|
        h[:project] = project
        h[:requested_path] = blob.path
        h[:issuable_reference_expansion_enabled] = true
        h[:cache_key] = ['blob', blob.id, 'commit', blob.commit_id, 'path', blob.path]
        h[:commit_id] = blob.commit_id
        if blob.container.is_a?(Snippet)
          h[:use_filename_in_anchor] = true
          # Include directives must not fall back to the parent project's repository
          h[:repository] = blob.container.repository
        end
      end
    end
  end
end
