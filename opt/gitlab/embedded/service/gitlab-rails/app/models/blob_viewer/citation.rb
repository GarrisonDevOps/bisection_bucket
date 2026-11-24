# frozen_string_literal: true

module BlobViewer # rubocop:disable Gitlab/BoundedContexts -- Moves together with the other BlobViewer classes
  class Citation < Base
    include Auxiliary
    include Static

    self.partial_name = 'citation'
    self.file_types = %i[citation]
    self.binary = false
  end
end
