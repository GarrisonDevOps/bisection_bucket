# frozen_string_literal: true

module DiffViewer
  class Image < Base
    include Rich
    include ClientSide

    self.partial_name = 'image'
    self.extensions = UploaderHelper::SAFE_IMAGE_EXT
    self.binary = true
    self.switcher_icon = 'doc-image'

    def self.switcher_title
      _('image diff')
    end

    def self.can_render?(diff_file, verify_binary: true)
      # When both blobs are missing, we often still have a textual diff that can
      # be displayed
      return false if diff_file.old_blob.nil? && diff_file.new_blob.nil?

      super
    end

    # Images render from blobs, so the diff collection's soft limits do not apply.
    # Generated files stay collapsed, because .gitattributes asked for it.
    def collapsed?
      return @collapsed if defined?(@collapsed)
      return @collapsed = true if diff_file.collapsed? && diff_file.generated?

      @collapsed = !diff_file.expanded? && diff_file.raw_size > collapse_limit
    end
  end
end
