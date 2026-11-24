# frozen_string_literal: true

module DeclarativeEnum
  module TranslatedDescriptions
    # Return list of dynamically translated descriptions.
    #
    # It is required to define descriptions with `N_(...)`.
    #
    # See https://github.com/grosser/fast_gettext#n_-and-nn_-make-dynamic-translations-available-to-the-parser
    def translated_descriptions
      definition.transform_values { |definition| _(definition[:description]) }
    end
  end
end
